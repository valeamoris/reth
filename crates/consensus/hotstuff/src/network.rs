//! `RLPx` custom subprotocol (`hotstuff/1`) for `HotStuff` P2P consensus messaging.

use alloy_primitives::{
    bytes::{Buf, BufMut, BytesMut},
    map::AddressMap,
    Address, B256,
};
use alloy_rlp::{Decodable, Encodable};
use futures_util::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol, Capability,
};
use reth_network::protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler};
use reth_network_api::{Direction, PeerId};
use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::{
    crypto::{peer_hello_digest, verify_peer_hello, ValidatorSigner},
    error::HotStuffError,
    types::{
        EpochChangeCert, NewView, PeerHello, Proposal, SyncBlocksRequest, SyncBlocksResponse,
        SyncStatus, TimeoutMsg, Vote, MAX_HOTSTUFF_MESSAGE_SIZE, MAX_SYNC_BATCH,
    },
};

const OUTBOUND_CHANNEL_CAPACITY: usize = 256;
const INBOUND_EVENT_CHANNEL_CAPACITY: usize = 1024;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireMessageId {
    Hello = 0x00,
    Proposal = 0x01,
    Vote = 0x02,
    Timeout = 0x03,
    NewView = 0x04,
    BlockRequest = 0x05,
    BlockResponse = 0x06,
    EpochChange = 0x07,
    Status = 0x08,
    SyncBlocksRequest = 0x09,
    SyncBlocksResponse = 0x0a,
}

impl WireMessageId {
    const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Hello),
            0x01 => Some(Self::Proposal),
            0x02 => Some(Self::Vote),
            0x03 => Some(Self::Timeout),
            0x04 => Some(Self::NewView),
            0x05 => Some(Self::BlockRequest),
            0x06 => Some(Self::BlockResponse),
            0x07 => Some(Self::EpochChange),
            0x08 => Some(Self::Status),
            0x09 => Some(Self::SyncBlocksRequest),
            0x0a => Some(Self::SyncBlocksResponse),
            _ => None,
        }
    }
}

/// Wire messages exchanged over the `hotstuff/1` `RLPx` subprotocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotStuffWireMessage {
    /// Authenticated validator identity handshake binding a validator address to an `RLPx`
    /// `PeerId`.
    Hello(PeerHello),
    /// Leader block or NIL suffix proposal.
    Proposal(Box<Proposal>),
    /// Validator vote sent to the next-view leader.
    Vote(Vote),
    /// Pacemaker timeout message.
    Timeout(Box<TimeoutMsg>),
    /// New-view notification with `high_qc` and optional `TimeoutCertificate`.
    NewView(Box<NewView>),
    /// Request for a missing `HotStuff` proposal by consensus `node_hash`.
    BlockRequest(B256),
    /// Response carrying a requested [`Proposal`].
    BlockResponse(Box<Proposal>),
    /// Proof of epoch boundary 3-chain finalization for epoch transition catch-up.
    EpochChange(Box<EpochChangeCert>),
    /// Sync status announcement carrying epoch, view, and latest finalized height.
    Status(SyncStatus),
    /// Request for a sequential batch of certified blocks for catch-up sync.
    SyncBlocksRequest(SyncBlocksRequest),
    /// Response carrying certified blocks and optional epoch boundary proof.
    SyncBlocksResponse(Box<SyncBlocksResponse>),
}

impl HotStuffWireMessage {
    /// Returns the `RLPx` capability `hotstuff/1`.
    pub const fn capability() -> Capability {
        Capability::new_static("hotstuff", 1)
    }

    /// Returns the `RLPx` protocol descriptor for `hotstuff/1` (11 message IDs).
    pub const fn protocol() -> Protocol {
        Protocol::new(Self::capability(), 11)
    }

    const fn message_id(&self) -> WireMessageId {
        match self {
            Self::Hello(_) => WireMessageId::Hello,
            Self::Proposal(_) => WireMessageId::Proposal,
            Self::Vote(_) => WireMessageId::Vote,
            Self::Timeout(_) => WireMessageId::Timeout,
            Self::NewView(_) => WireMessageId::NewView,
            Self::BlockRequest(_) => WireMessageId::BlockRequest,
            Self::BlockResponse(_) => WireMessageId::BlockResponse,
            Self::EpochChange(_) => WireMessageId::EpochChange,
            Self::Status(_) => WireMessageId::Status,
            Self::SyncBlocksRequest(_) => WireMessageId::SyncBlocksRequest,
            Self::SyncBlocksResponse(_) => WireMessageId::SyncBlocksResponse,
        }
    }

    /// Encodes this message into a framed `RLPx` buffer `[msg_id | rlp_payload]`.
    pub fn encode(&self) -> Result<BytesMut, HotStuffError> {
        let mut buf = BytesMut::with_capacity(256);
        buf.put_u8(self.message_id() as u8);
        match self {
            Self::Hello(m) => m.encode(&mut buf),
            Self::Proposal(m) | Self::BlockResponse(m) => m.encode(&mut buf),
            Self::Vote(m) => m.encode(&mut buf),
            Self::Timeout(m) => m.encode(&mut buf),
            Self::NewView(m) => m.encode(&mut buf),
            Self::BlockRequest(hash) => hash.encode(&mut buf),
            Self::EpochChange(cert) => cert.encode(&mut buf),
            Self::Status(status) => status.encode(&mut buf),
            Self::SyncBlocksRequest(req) => req.encode(&mut buf),
            Self::SyncBlocksResponse(resp) => resp.encode(&mut buf),
        }
        if buf.len() > MAX_HOTSTUFF_MESSAGE_SIZE {
            return Err(HotStuffError::MessageTooLarge {
                size: buf.len(),
                max: MAX_HOTSTUFF_MESSAGE_SIZE,
            });
        }
        Ok(buf)
    }

    /// Decodes a framed `RLPx` payload `[msg_id | rlp_payload]`, enforcing
    /// [`MAX_HOTSTUFF_MESSAGE_SIZE`].
    pub fn decode(mut buf: &[u8]) -> Result<Self, HotStuffError> {
        if buf.len() > MAX_HOTSTUFF_MESSAGE_SIZE {
            return Err(HotStuffError::MessageTooLarge {
                size: buf.len(),
                max: MAX_HOTSTUFF_MESSAGE_SIZE,
            });
        }
        if buf.is_empty() {
            return Err(HotStuffError::RlpDecode("empty HotStuff wire frame".to_string()));
        }
        let id = WireMessageId::from_u8(buf[0])
            .ok_or_else(|| HotStuffError::RlpDecode(format!("unknown message id {}", buf[0])))?;
        buf.advance(1);

        let slice = &mut buf;
        let msg = match id {
            WireMessageId::Hello => Self::Hello(PeerHello::decode(slice).map_err(rlp_err)?),
            WireMessageId::Proposal => {
                Self::Proposal(Box::new(Proposal::decode(slice).map_err(rlp_err)?))
            }
            WireMessageId::Vote => Self::Vote(Vote::decode(slice).map_err(rlp_err)?),
            WireMessageId::Timeout => {
                Self::Timeout(Box::new(TimeoutMsg::decode(slice).map_err(rlp_err)?))
            }
            WireMessageId::NewView => {
                Self::NewView(Box::new(NewView::decode(slice).map_err(rlp_err)?))
            }
            WireMessageId::BlockRequest => {
                Self::BlockRequest(B256::decode(slice).map_err(rlp_err)?)
            }
            WireMessageId::BlockResponse => {
                Self::BlockResponse(Box::new(Proposal::decode(slice).map_err(rlp_err)?))
            }
            WireMessageId::EpochChange => {
                Self::EpochChange(Box::new(EpochChangeCert::decode(slice).map_err(rlp_err)?))
            }
            WireMessageId::Status => Self::Status(SyncStatus::decode(slice).map_err(rlp_err)?),
            WireMessageId::SyncBlocksRequest => {
                Self::SyncBlocksRequest(SyncBlocksRequest::decode(slice).map_err(rlp_err)?)
            }
            WireMessageId::SyncBlocksResponse => {
                let resp = SyncBlocksResponse::decode(slice).map_err(rlp_err)?;
                if resp.blocks.len() > MAX_SYNC_BATCH {
                    return Err(HotStuffError::RlpDecode(format!(
                        "sync batch length {} exceeds max {MAX_SYNC_BATCH}",
                        resp.blocks.len()
                    )));
                }
                Self::SyncBlocksResponse(Box::new(resp))
            }
        };
        if !slice.is_empty() {
            return Err(HotStuffError::RlpDecode(format!(
                "trailing {} bytes in HotStuff wire message",
                slice.len()
            )));
        }
        Ok(msg)
    }
}

fn rlp_err(err: alloy_rlp::Error) -> HotStuffError {
    HotStuffError::RlpDecode(err.to_string())
}

/// Events emitted by active `hotstuff/1` `RLPx` peer connections to the consensus driver.
#[derive(Debug)]
pub enum HotStuffPeerEvent {
    /// A peer negotiated the `hotstuff/1` `RLPx` subprotocol.
    Connected {
        /// Remote `RLPx` peer ID.
        peer_id: PeerId,
        /// Outbound frame sender for this peer connection.
        outbound: mpsc::Sender<BytesMut>,
    },
    /// A valid decoded [`HotStuffWireMessage`] arrived from `peer_id`.
    Message {
        /// Sender peer ID.
        peer_id: PeerId,
        /// Decoded consensus message.
        message: HotStuffWireMessage,
    },
    /// A `hotstuff/1` peer connection closed.
    Disconnected {
        /// Disconnected peer ID.
        peer_id: PeerId,
    },
}

/// `RLPx` [`ProtocolHandler`] registering the `hotstuff/1` subprotocol on Reth's `NetworkManager`.
#[derive(Debug, Clone)]
pub struct HotStuffRlpxHandler {
    events: mpsc::Sender<HotStuffPeerEvent>,
}

impl HotStuffRlpxHandler {
    /// Creates a new [`HotStuffRlpxHandler`] paired with its inbound [`HotStuffPeerEvent`]
    /// receiver.
    pub fn new() -> (Self, mpsc::Receiver<HotStuffPeerEvent>) {
        let (tx, rx) = mpsc::channel(INBOUND_EVENT_CHANNEL_CAPACITY);
        (Self { events: tx }, rx)
    }
}

impl ProtocolHandler for HotStuffRlpxHandler {
    type ConnectionHandler = HotStuffRlpxConnectionHandler;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(HotStuffRlpxConnectionHandler { events: self.events.clone() })
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(HotStuffRlpxConnectionHandler { events: self.events.clone() })
    }
}

/// Per-connection `RLPx` handler spawning [`HotStuffRlpxConnection`].
#[derive(Debug)]
pub struct HotStuffRlpxConnectionHandler {
    events: mpsc::Sender<HotStuffPeerEvent>,
}

impl ConnectionHandler for HotStuffRlpxConnectionHandler {
    type Connection = HotStuffRlpxConnection;

    fn protocol(&self) -> Protocol {
        HotStuffWireMessage::protocol()
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        _direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        let (tx, rx) = mpsc::channel(OUTBOUND_CHANNEL_CAPACITY);
        if self.events.try_send(HotStuffPeerEvent::Connected { peer_id, outbound: tx }).is_err() {
            warn!(target: "consensus::hotstuff", %peer_id, "HotStuff peer event channel full on connect");
        }
        HotStuffRlpxConnection {
            conn,
            peer_id,
            outbound: ReceiverStream::new(rx),
            events: self.events,
            disconnected_sent: false,
        }
    }
}

/// Active multiplexed `RLPx` stream for the `hotstuff/1` subprotocol.
#[derive(Debug)]
pub struct HotStuffRlpxConnection {
    conn: ProtocolConnection,
    peer_id: PeerId,
    outbound: ReceiverStream<BytesMut>,
    events: mpsc::Sender<HotStuffPeerEvent>,
    disconnected_sent: bool,
}

impl Drop for HotStuffRlpxConnection {
    fn drop(&mut self) {
        if !self.disconnected_sent {
            self.disconnected_sent = true;
            let _ = self.events.try_send(HotStuffPeerEvent::Disconnected { peer_id: self.peer_id });
        }
    }
}

impl Stream for HotStuffRlpxConnection {
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Poll::Ready(Some(frame)) = this.outbound.poll_next_unpin(cx) {
                return Poll::Ready(Some(frame));
            }

            match this.conn.poll_next_unpin(cx) {
                Poll::Ready(Some(raw)) => {
                    match HotStuffWireMessage::decode(&raw) {
                        Ok(message) => {
                            if this
                                .events
                                .try_send(HotStuffPeerEvent::Message {
                                    peer_id: this.peer_id,
                                    message,
                                })
                                .is_err()
                            {
                                warn!(
                                    target: "consensus::hotstuff",
                                    peer_id = %this.peer_id,
                                    "Dropping inbound HotStuff message: event channel full"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(
                                target: "consensus::hotstuff",
                                peer_id = %this.peer_id,
                                %err,
                                "Malformed HotStuff RLPx wire frame"
                            );
                        }
                    }
                    // Continue polling inbound/outbound channels without returning Poll::Pending.
                }
                Poll::Ready(None) => {
                    if !this.disconnected_sent {
                        this.disconnected_sent = true;
                        let _ = this
                            .events
                            .try_send(HotStuffPeerEvent::Disconnected { peer_id: this.peer_id });
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Manages active `hotstuff/1` peers and authenticated `validator -> PeerId` routing.
#[derive(Debug)]
pub struct HotStuffNetworkBridge {
    local_peer_id: PeerId,
    signer: Option<ValidatorSigner>,
    peers: HashMap<PeerId, mpsc::Sender<BytesMut>>,
    validator_peers: AddressMap<PeerId>,
}

impl HotStuffNetworkBridge {
    /// Creates a new [`HotStuffNetworkBridge`] for `local_peer_id`.
    pub fn new(local_peer_id: PeerId, signer: Option<ValidatorSigner>) -> Self {
        Self {
            local_peer_id,
            signer,
            peers: HashMap::new(),
            validator_peers: AddressMap::default(),
        }
    }

    /// Registers a newly connected peer and sends our signed [`PeerHello`] if configured.
    pub fn on_peer_connected(&mut self, peer_id: PeerId, outbound: mpsc::Sender<BytesMut>) {
        self.peers.insert(peer_id, outbound);
        if let Some(signer) = &self.signer {
            let digest = peer_hello_digest(signer.address(), &self.local_peer_id);
            let hello = PeerHello {
                validator: signer.address(),
                peer_id: self.local_peer_id,
                signature: signer.sign_digest(digest),
            };
            self.send_to_peer(peer_id, &HotStuffWireMessage::Hello(hello));
        }
        debug!(target: "consensus::hotstuff", %peer_id, total_peers = self.peers.len(), "HotStuff peer connected");
    }

    /// Removes a disconnected peer and any validator-to-peer mappings referencing it.
    pub fn on_peer_disconnected(&mut self, peer_id: PeerId) {
        self.peers.remove(&peer_id);
        self.validator_peers.retain(|_, pid| *pid != peer_id);
        debug!(target: "consensus::hotstuff", %peer_id, total_peers = self.peers.len(), "HotStuff peer disconnected");
    }

    /// Authenticates a received [`PeerHello`] and records `validator -> peer_id`.
    pub fn on_peer_hello(
        &mut self,
        peer_id: PeerId,
        hello: PeerHello,
    ) -> Result<Address, HotStuffError> {
        if hello.peer_id != peer_id {
            return Err(HotStuffError::InvalidSignature(
                "PeerHello peer_id does not match RLPx session PeerId".to_string(),
            ));
        }
        verify_peer_hello(&hello)?;
        self.validator_peers.insert(hello.validator, peer_id);
        Ok(hello.validator)
    }

    /// Returns the number of currently connected `hotstuff/1` peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Sends a message to a specific `RLPx` `PeerId`.
    pub fn send_to_peer(&self, peer_id: PeerId, msg: &HotStuffWireMessage) {
        let Some(tx) = self.peers.get(&peer_id) else {
            return;
        };
        match msg.encode() {
            Ok(frame) => {
                if tx.try_send(frame).is_err() {
                    warn!(target: "consensus::hotstuff", %peer_id, "Dropping HotStuff message: peer outbound channel full");
                }
            }
            Err(err) => {
                warn!(target: "consensus::hotstuff", %err, "Failed to encode HotStuff message");
            }
        }
    }

    /// Sends a message directly to `validator` if its `PeerId` is authenticated, or broadcasts
    /// otherwise.
    pub fn send_to_validator(&self, validator: Address, msg: &HotStuffWireMessage) {
        if let Some(&peer_id) = self.validator_peers.get(&validator) {
            self.send_to_peer(peer_id, msg);
        } else {
            self.broadcast(msg);
        }
    }

    /// Broadcasts a message to every connected `hotstuff/1` peer.
    pub fn broadcast(&self, msg: &HotStuffWireMessage) {
        if self.peers.is_empty() {
            return;
        }
        let frame = match msg.encode() {
            Ok(frame) => frame,
            Err(err) => {
                warn!(target: "consensus::hotstuff", %err, "Failed to encode HotStuff broadcast");
                return;
            }
        };
        for (&peer_id, tx) in &self.peers {
            if tx.try_send(frame.clone()).is_err() {
                warn!(target: "consensus::hotstuff", %peer_id, "Dropping HotStuff broadcast: peer outbound channel full");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HotStuffNodeHeader, QuorumCertificate};
    use alloy_primitives::{Bytes, FixedBytes};

    #[test]
    fn wire_message_encode_decode_roundtrip() {
        let qc = QuorumCertificate::epoch_genesis(0, B256::repeat_byte(0x01), 0);
        let proposal = Proposal {
            header: HotStuffNodeHeader {
                epoch: 0,
                view: 1,
                parent_node_hash: qc.node_hash,
                justify_qc_hash: qc.hash(),
                exec_block_hash: B256::repeat_byte(0x02),
                exec_block_number: 1,
                proposer: Address::with_last_byte(1),
                is_nil: false,
            },
            justify_qc: qc,
            block_rlp: Bytes::from_static(&[1, 2, 3, 4]),
            requests: Vec::new(),
            signature: FixedBytes::repeat_byte(0xaa),
            timeout_cert: None,
        };

        let wire = HotStuffWireMessage::Proposal(Box::new(proposal));
        let encoded = wire.encode().unwrap();
        let decoded = HotStuffWireMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, wire);

        let oversized = vec![0u8; MAX_HOTSTUFF_MESSAGE_SIZE + 1];
        assert!(matches!(
            HotStuffWireMessage::decode(&oversized).unwrap_err(),
            HotStuffError::MessageTooLarge { .. }
        ));
    }

    #[test]
    fn sync_wire_messages_roundtrip() {
        use crate::types::SyncedBlock;

        let qc = QuorumCertificate::epoch_genesis(1, B256::repeat_byte(0x02), 3);
        let header = HotStuffNodeHeader {
            epoch: 1,
            view: 2,
            parent_node_hash: qc.node_hash,
            justify_qc_hash: qc.hash(),
            exec_block_hash: B256::repeat_byte(0x04),
            exec_block_number: 4,
            proposer: Address::with_last_byte(2),
            is_nil: false,
        };

        let status = HotStuffWireMessage::Status(SyncStatus {
            epoch: 1,
            view: 5,
            finalized_number: 4,
            finalized_hash: B256::repeat_byte(0x04),
        });
        let req = HotStuffWireMessage::SyncBlocksRequest(SyncBlocksRequest {
            from_block: 1,
            max_blocks: 16,
        });
        let resp = HotStuffWireMessage::SyncBlocksResponse(Box::new(SyncBlocksResponse {
            blocks: vec![SyncedBlock {
                block_rlp: Bytes::from_static(&[0xaa, 0xbb]),
                requests: Vec::new(),
                header,
                qc,
            }],
            epoch_cert: None,
        }));

        for msg in [status, req, resp] {
            let encoded = msg.encode().unwrap();
            let decoded = HotStuffWireMessage::decode(&encoded).unwrap();
            assert_eq!(decoded, msg);
        }
    }
}
