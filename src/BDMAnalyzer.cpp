#nclude "BDMAnalyzer.h"
#include "BDMAnalyzerSettings.h"
#include <AnalyzerChannelData.h>

BDMAnalyzer::BDMAnalyzer()
:	Analyzer2(),  
	mSettings(),
	mSimulationInitilized( false )
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
	// SetupResults is called each time the analyzer is run. Because the same instance can be used for multiple runs, we need to clear the results each time.
	mResults.reset(new BDMAnalyzerResults( this, &mSettings ));
	SetAnalyzerResults( mResults.get() );
	mResults->AddChannelBubblesWillAppearOn( mSettings.mDSDIChannel );
	mResults->AddChannelBubblesWillAppearOn( mSettings.mDSDOChannel );
}

void BDMAnalyzer::SyncChannels(U64 sampleNum)
{
		mDSDI->AdvanceToAbsPosition(sampleNum);  
	mDSDO->AdvanceToAbsPosition(sampleNum);  
	mDSCK->AdvanceToAbsPosition(sampleNum);  
	mHRESET->AdvanceToAbsPosition(sampleNum);  
		mSRESET->AdvanceToAbsPosition(sampleNum);
	mVLFS0 ->AdvanceToAbsPosition(sampleNum);
	mVLFS1 ->AdvanceToAbsPosition(sampleNum);
}

/*
 * Ensure current bitstate is valid within tolerance
 * returns False if there is a transition within tolerance
 * returns True if there is no transition
 */
bool BDMAnalyzer::ToleranceCheck(AnalyzerChannelData* channel) {
	//here we're checking within tolerance and +1 to ensure we don't pick up a single sample glich
	return ( !channel->WouldAdvancingCauseTransition(mSettings.mSampleTolerance) //if it transitions within tolerance 
		&& !channel->WouldAdvancingCauseTransition(mSettings.mSampleTolerance + 2)); //and it doesn't transition back in the next sample
}

void BDMAnalyzer::CollectPackets()
{
	U8 mode_control = 0;
	U8 status = 0;
	U32 dsdi_packet = 0;
	U32 dsdo_packet = 0;
	U64 starting_sample_control = mDSDI->GetSampleNumber();

	if( mDSDO->GetBitState() == BIT_LOW) { //target ready
		
		for (U32 i=0; i<3; i++)
		{
			//if we detect a change within our tolerance, we'll assign to that changed state
			// ie, if we see DSDI changes in one sample from where we're currently sampling,
			//	and DSDI is low, the next sample will have DSDI high. We'll use that
			if( this->ToleranceCheck(mDSDI) ) {
				mode_control = (mode_control << 1) | mDSDI->GetBitState();
			} else {
				
				mode_control = (mode_control << 1) | !mDSDI->GetBitState(); 
			}
		
			if( this->ToleranceCheck(mDSDO) ) {
				status = (status << 1) | mDSDO->GetBitState()  ;
			} else {
				status = (status << 1) | !mDSDO->GetBitState()  ;
			}
			//status = (status << 1) | mDSDO->GetBitState();
			/*
			* In a case where DSDI transitions high before DSCK falling edge
			* advance an extra edge to align back with clock. 
			* special case because we enter CollectPackets() via a trigger on DSDI rising edge
			*/
			if ( mDSCK->WouldAdvancingCauseTransition(mSettings.mSampleTolerance) ) mDSCK->AdvanceToNextEdge(); 

			mDSCK->AdvanceToNextEdge();
			mDSCK->AdvanceToNextEdge();
			this->SyncChannels(mDSCK->GetSampleNumber());
			mDSDI->Advance(mSettings.mSampleTolerance);
			mDSDO->Advance(mSettings.mSampleTolerance);
			mResults->AddMarker(mDSDI->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDIChannel); 
			mResults->AddMarker(mDSDO->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDOChannel); 
		}

		U8 pkt_len = ((mode_control & 0x2 ) >> 1) ? 7 : 32; //mode bit determines packet length
		
		U64 starting_sample_packet = mDSDI->GetSampleNumber();
		for (U32 i=0; i<pkt_len; i++) {
			dsdi_packet = (dsdi_packet << 1) | mDSDI->GetBitState();
			dsdo_packet = (dsdo_packet << 1) | mDSDO->GetBitState();
			mDSCK->AdvanceToNextEdge();
			mDSCK->AdvanceToNextEdge();
			this->SyncChannels(mDSCK->GetSampleNumber());
			mDSDI->Advance(mSettings.mSampleTolerance);
			mDSDO->Advance(mSettings.mSampleTolerance);
			mResults->AddMarker(mDSDI->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDIChannel); 
			mResults->AddMarker(mDSDO->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDOChannel); 
		}

		Frame mode_control_frame;
		mode_control_frame.mData1 = mode_control;
		mode_control_frame.mFlags = (mode_control & 0x2) >> 1; 
		mode_control_frame.mStartingSampleInclusive = starting_sample_control;
		mode_control_frame.mEndingSampleInclusive = starting_sample_packet;
		mResults->AddFrame( mode_control_frame );
		
		Frame dsdi_pkt_frame;
		dsdi_pkt_frame.mData1 = dsdi_packet;
		dsdi_pkt_frame.mFlags = dsdi_packet; 
		dsdi_pkt_frame.mStartingSampleInclusive = starting_sample_packet;
		dsdi_pkt_frame.mEndingSampleInclusive = mDSDI->GetSampleNumber();
		mResults->AddFrame( dsdi_pkt_frame );


		Frame status_frame;
		status_frame.mData2 = status;
		status_frame.mFlags = (status & 0x2) >> 1; 
		status_frame.mStartingSampleInclusive = starting_sample_control;
		status_frame.mEndingSampleInclusive = starting_sample_packet;
		mResults->AddFrame( status_frame );

		Frame dsdo_pkt_frame;
		dsdo_pkt_frame.mData2 = dsdo_packet;
		dsdo_pkt_frame.mFlags = (status & 0x2) >> 1; 
		dsdo_pkt_frame.mStartingSampleInclusive = starting_sample_packet;
		dsdo_pkt_frame.mEndingSampleInclusive = mDSDO->GetSampleNumber();
		mResults->AddFrame( dsdo_pkt_frame );


		//reverse byte order for bytearray
		U8 dsdipktbytearray[4];
		U8 dsdopktbytearray[4];
		for(U8 i = 0; i<4 ; i++) 
		{
			dsdipktbytearray[3-i] = (U8)((dsdi_packet >> (i*8)) & 0xFF);
			dsdopktbytearray[3-i] = (U8)((dsdo_packet >> (i*8)) & 0xFF);
		}

		//organize into framev2 for easy viewing/exporting
		FrameV2 dsdiFv2;
		dsdiFv2.AddByte("Mode", (mode_control & 0x2) >> 1);
		dsdiFv2.AddByte("Control", (mode_control & 0x1));
		dsdiFv2.AddByteArray("Instruction", (const U8*)dsdipktbytearray, 4);
		mResults->AddFrameV2( dsdiFv2, "DSDI", mode_control_frame.mStartingSampleInclusive, dsdi_pkt_frame.mEndingSampleInclusive);

		FrameV2 dsdoFv2;
		dsdoFv2.AddByte("Status 1", (status & 0x2) >> 1);
		dsdoFv2.AddByte("Status 2", (status & 0x1));
		dsdoFv2.AddByteArray("Data", (const U8*)dsdopktbytearray, 4);
		mResults->AddFrameV2( dsdoFv2, "DSDO", status_frame.mStartingSampleInclusive, dsdo_pkt_frame.mEndingSampleInclusive);



		mResults->CommitResults();
		//ReportProgress( frame.mEndingSampleInclusive );
	}
}


void BDMAnalyzer::WorkerThread()
{
	mSampleRateHz = GetSampleRate();


	mDSDI   = GetAnalyzerChannelData( mSettings.mDSDIChannel);
	mDSDO   = GetAnalyzerChannelData( mSettings.mDSDOChannel);
	mDSCK   = GetAnalyzerChannelData( mSettings.mDSCKChannel);     
	mHRESET = GetAnalyzerChannelData( mSettings.mHRESETChannel);
	mSRESET = GetAnalyzerChannelData( mSettings.mSRESETChannel);
	mVLFS0  = GetAnalyzerChannelData( mSettings.mVFLS0Channel);
	mVLFS1  = GetAnalyzerChannelData( mSettings.mVFLS1Channel);

	bdm_state = BOOT;

	if( mDSDI->GetBitState() == BIT_LOW )
		mDSDI->AdvanceToNextEdge();

	U32 samples_per_bit = mSampleRateHz / mSettings.mBitRate;
	U32 samples_to_first_center_of_first_data_bit = U32( 1.5 * double( mSampleRateHz ) / double( mSettings.mBitRate ) );

	for( ; ; )
	{
		switch(bdm_state) {
			case BOOT:
				//shortcut to ignore clock select from lauterbach
				mDSCK->AdvanceToNextEdge(); //find first dsck assertion
				while( mDSCK->GetBitState() != BIT_LOW) mDSCK->AdvanceToNextEdge(); //find end of assertion
				//we're ignoring the freeze and reset signals at the moment, and assuming async
				//we're also assuming the resets are negated and the freezes asserted here, and maybe
				//DSDO asserted low.
				this->SyncChannels(mDSCK->GetSampleNumber()); //find where that is and syncronize positions
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
				mDSDI->Advance(5);
				if (mDSDI->GetBitState() == BIT_LOW) mDSDI->AdvanceToNextEdge(); //start bit
				mResults->AddMarker(mDSDI->GetSampleNumber(), AnalyzerResults::Dot, mSettings.mDSDIChannel); 
				this->SyncChannels(mDSDI->GetSampleNumber());
				bdm_state = PKT_START;
				break;
			case PKT_START:
				this->CollectPackets();
				bdm_state = CORE_READY;
				break;

		}
	}
}

bool BDMAnalyzer::NeedsRerun()
{
	return false;
}

U32 BDMAnalyzer::GenerateSimulationData( U64 minimum_sample_index, U32 device_sample_rate, SimulationChannelDescriptor** simulation_channels )
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
