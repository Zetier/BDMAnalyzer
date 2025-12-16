#include "BDMAnalyzer.h"
#include "BDMAnalyzerSettings.h"
#include <AnalyzerChannelData.h>

BDMAnalyzer::BDMAnalyzer() : Analyzer2(), mSettings(), mSimulationInitilized( false )
{
    SetAnalyzerSettings( &mSettings );
    UseFrameV2();
}

BDMAnalyzer::~BDMAnalyzer()
{
    KillThread();
}

void BDMAnalyzer::SetupResults()
{
    // SetupResults is called each time the analyzer is run.
    // Because the same instance can be used for multiple runs,
    // we need to clear the results each time.
    mResults.reset( new BDMAnalyzerResults( this, &mSettings ) );
    SetAnalyzerResults( mResults.get() );
    mResults->AddChannelBubblesWillAppearOn( mSettings.mDSDIChannel );
    mResults->AddChannelBubblesWillAppearOn( mSettings.mDSDOChannel );
}

void BDMAnalyzer::SyncChannels( U64 sampleNum )
{
    mDSDI->AdvanceToAbsPosition( sampleNum );
    mDSDO->AdvanceToAbsPosition( sampleNum );
    mDSCK->AdvanceToAbsPosition( sampleNum );
    mHRESET->AdvanceToAbsPosition( sampleNum );
    mSRESET->AdvanceToAbsPosition( sampleNum );
    mVLFS0->AdvanceToAbsPosition( sampleNum );
    mVLFS1->AdvanceToAbsPosition( sampleNum );
}

void BDMAnalyzer::CollectPackets()
{
    U8 mode_control = 0;
    U8 status = 0;
    U32 dsdi_packet = 0;
    U32 dsdo_packet = 0;
    U64 starting_sample_control = mDSDI->GetSampleNumber();

    if( mDSDO->GetBitState() == BIT_LOW )
    {
        // target ready

        // read start, mode, control, and status bits
        for( S32 i = 2; i >= 0; i-- )
        {
            mDSCK->AdvanceToNextEdge();
            this->SyncChannels( mDSCK->GetSampleNumber() );
            mResults->AddMarker( mDSDI->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDIChannel );
            mResults->AddMarker( mDSDO->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDOChannel );

            mode_control += mDSDI->GetBitState() << i;
            status += mDSDO->GetBitState() << i;
            mDSCK->AdvanceToNextEdge();
        }

        this->SyncChannels( mDSCK->GetSampleNumber() );
        U64 starting_sample_packet = mDSDI->GetSampleNumber();

        U8 pkt_len = ( ( mode_control & 0x2 ) >> 1 ) ? 7 : 32; // mode bit determines packet length
        for( S32 i = 0; i < pkt_len - 1; i++ )                 // pkt_len-1 as we want to handle the final bit separately
        {
            mDSCK->AdvanceToNextEdge();
            this->SyncChannels( mDSCK->GetSampleNumber() );
            mResults->AddMarker( mDSDI->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDIChannel );
            mResults->AddMarker( mDSDO->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDOChannel );
            dsdi_packet = ( dsdi_packet << 1 ) | mDSDI->GetBitState();
            dsdo_packet = ( dsdo_packet << 1 ) | mDSDO->GetBitState();
            mDSCK->AdvanceToNextEdge();
        }
        /*
        target device sometimes blips DSDO to create falling edge indicating
        that it is ready to receive another command. It can happen very
        close to the rising edge of DSCK so for the last bit we will
        read the value one sample prior to the DSCK rising edge
        */
        mDSCK->AdvanceToAbsPosition( mDSCK->GetSampleOfNextEdge() - 1 );
        this->SyncChannels( mDSCK->GetSampleNumber() );
        mResults->AddMarker( mDSDI->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDIChannel );
        mResults->AddMarker( mDSDO->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDOChannel );
        dsdi_packet = ( dsdi_packet << 1 ) | mDSDI->GetBitState();
        dsdo_packet = ( dsdo_packet << 1 ) | mDSDO->GetBitState();

        // advance because we still have to get to the rising edge for this bit
        mDSCK->AdvanceToNextEdge();
        U64 ending_sample_packet = mDSCK->GetSampleNumber();
        this->SyncChannels( mDSCK->GetSampleNumber() );

        Frame mode_control_frame;
        mode_control_frame.mData1 = mode_control;
        mode_control_frame.mData2 = status;
        mode_control_frame.mFlags = ( mode_control & 0x2 ) >> 1;
        mode_control_frame.mStartingSampleInclusive = starting_sample_control;
        mode_control_frame.mEndingSampleInclusive = starting_sample_packet;
        mResults->AddFrame( mode_control_frame );
        mResults->CommitResults();

        Frame dsdi_pkt_frame;
        dsdi_pkt_frame.mData1 = dsdi_packet;
        dsdi_pkt_frame.mData2 = dsdo_packet;
        dsdi_pkt_frame.mFlags = dsdi_packet;
        dsdi_pkt_frame.mStartingSampleInclusive = starting_sample_packet;
        dsdi_pkt_frame.mEndingSampleInclusive = ending_sample_packet;
        mResults->AddFrame( dsdi_pkt_frame );
        mResults->CommitResults();

        // reverse byte order for bytearray
        U8 dsdipktbytearray[ 4 ];
        U8 dsdopktbytearray[ 4 ];
        for( U8 i = 0; i < 4; i++ )
        {
            dsdipktbytearray[ 3 - i ] = ( U8 )( ( dsdi_packet >> ( i * 8 ) ) & 0xFF );
            dsdopktbytearray[ 3 - i ] = ( U8 )( ( dsdo_packet >> ( i * 8 ) ) & 0xFF );
        }

        FrameV2 bdmMessage;
        bdmMessage.AddByte( "Mode", ( mode_control & 0x2 ) >> 1 );
        bdmMessage.AddByte( "Control", ( mode_control & 0x1 ) );
        bdmMessage.AddByteArray( "Instruction", ( const U8* )dsdipktbytearray, 4 );
        bdmMessage.AddByte( "Status 1", ( status & 0x2 ) >> 1 );
        bdmMessage.AddByte( "Status 2", ( status & 0x1 ) );
        bdmMessage.AddByteArray( "Response", ( const U8* )dsdopktbytearray, 4 );
        mResults->AddFrameV2( bdmMessage, ( ( mode_control & 0x2 ) >> 1 ) ? "Trap" : "Instruction",
                              mode_control_frame.mStartingSampleInclusive, dsdi_pkt_frame.mEndingSampleInclusive );

        mResults->CommitResults();
    }
}


void BDMAnalyzer::WorkerThread()
{
    mSampleRateHz = GetSampleRate();


    mDSDI = GetAnalyzerChannelData( mSettings.mDSDIChannel );
    mDSDO = GetAnalyzerChannelData( mSettings.mDSDOChannel );
    mDSCK = GetAnalyzerChannelData( mSettings.mDSCKChannel );
    mHRESET = GetAnalyzerChannelData( mSettings.mHRESETChannel );
    mSRESET = GetAnalyzerChannelData( mSettings.mSRESETChannel );
    mVLFS0 = GetAnalyzerChannelData( mSettings.mVFLS0Channel );
    mVLFS1 = GetAnalyzerChannelData( mSettings.mVFLS1Channel );

    bdm_state = BOOT;

    for( ;; )
    {
        switch( bdm_state )
        {
        case BOOT:
            // shortcut to ignore clock select from lauterbach
            mDSCK->AdvanceToNextEdge(); // find first dsck assertion
            while( mDSCK->GetBitState() != BIT_LOW )
                mDSCK->AdvanceToNextEdge(); // find end of assertion
            // we're ignoring the freeze and reset signals at the moment, and assuming async
            // we're also assuming the resets are negated and the freezes asserted here, and maybe
            // DSDO asserted low.
            this->SyncChannels( mDSCK->GetSampleNumber() ); // find where that is and syncronize positions
            mResults->AddMarker( mDSCK->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSCKChannel );

            bdm_state = CORE_READY;
            break;
        case CLKSLCT:
            break;
        case COREBOOTHOLD:
            break;
        case DBG_MD_SET:
            break;
        case CORE_READY_HOLD:
            break;
        case CORE_READY:
            mDSDI->AdvanceToNextEdge();
            if( mDSDI->GetBitState() == BIT_LOW )
                mDSDI->AdvanceToNextEdge(); // start bit
            this->SyncChannels( mDSDI->GetSampleNumber() );
            bdm_state = PKT_START;
            break;
        case PKT_START:
            this->CollectPackets();
            if( mDSDI->GetBitState() == BIT_HIGH )
            {
                // last bit was high meaning if another message follows immediately
                // there won't be a DSDI rising edge to search for in CORE_READY
                mDSCK->AdvanceToNextEdge();
                this->SyncChannels( mDSCK->GetSampleNumber() );
                if( mDSDI->GetBitState() == BIT_HIGH )
                {
                    // DSDI is still high at DSCK falling edge, which means we
                    // are at the start of another message, stay in PKT_START
                    break;
                }
            }
            bdm_state = CORE_READY;
            break;
        }
    }
}

bool BDMAnalyzer::NeedsRerun()
{
    return false;
}

U32 BDMAnalyzer::GenerateSimulationData( U64 minimum_sample_index, U32 device_sample_rate,
                                         SimulationChannelDescriptor** simulation_channels )
{
    if( mSimulationInitilized == false )
    {
        mSimulationDataGenerator.Initialize( GetSimulationSampleRate(), &mSettings );
        mSimulationInitilized = true;
    }

    return mSimulationDataGenerator.GenerateSimulationData( minimum_sample_index, device_sample_rate, simulation_channels );
}

U32 BDMAnalyzer::GetMinimumSampleRateHz()
{
    return mSettings.mBitRate * 4;
}

const char* BDMAnalyzer::GetAnalyzerName() const
{
    return "BDM";
}

const char* GetAnalyzerName()
{
    return "BDM";
}

Analyzer* CreateAnalyzer()
{
    return new BDMAnalyzer();
}

void DestroyAnalyzer( Analyzer* analyzer )
{
    delete analyzer;
}
