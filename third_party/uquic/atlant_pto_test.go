package quic

import (
	"testing"
	"github.com/refraction-networking/uquic/internal/monotime"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestAtlantBrowserPTOForcesPingWhenNoDataRemain(t *testing.T) {
	ctrl:=gomock.NewController(t)
	tp:=newTestPacketPacker(t,ctrl,protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(ctrl),nil).Times(2)
	tp.framer.EXPECT().HasData().Times(2)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42),protocol.PacketNumberLen2).Times(2)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT,gomock.Any(),true).Times(2)
	packer:=newUPacketPacker(tp.packer,&QUICSpec{})
	packet,err:=packer.PackPTOProbePacket(protocol.Encryption1RTT,1250,false,monotime.Now(),protocol.Version1)
	require.NoError(t,err);require.Nil(t,packet)
	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	packet,err=packer.PackPTOProbePacket(protocol.Encryption1RTT,1250,true,monotime.Now(),protocol.Version1)
	require.NoError(t,err);require.NotNil(t,packet)
	require.Len(t,packet.shortHdrPacket.Frames,1)
	require.IsType(t,&wire.PingFrame{},packet.shortHdrPacket.Frames[0].Frame)
}
