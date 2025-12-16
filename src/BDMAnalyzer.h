#ifndef BDM_ANALYZER_H
#define BDM_ANALYZER_H

#include <Analyzer.h>
#include "BDMAnalyzerSettings.h"
#include "BDMAnalyzerResults.h"
#include "BDMSimulationDataGenerator.h"
#include <memory>


enum BDM_State
{
    BOOT,
    CLKSLCT,
    COREBOOTHOLD,
    DBG_MD_SET,
    CORE_READY_HOLD,
    CORE_READY,
    PKT_START,
};

enum To_Check
{
    DSDI,
    DSDO,
    DSCK,
};

class ANALYZER_EXPORT BDMAnalyzer : public Analyzer2
{
  public:
    BDMAnalyzer();
    virtual ~BDMAnalyzer();

    virtual void SetupResults();
    virtual void WorkerThread();

    virtual U32 GenerateSimulationData( U64 newest_sample_requested, U32 sample_rate, SimulationChannelDescriptor** simulation_channels );
    virtual U32 GetMinimumSampleRateHz();

    virtual const char* GetAnalyzerName() const;
    virtual bool NeedsRerun();
    virtual void SyncChannels( U64 sampleNum );
    virtual void CollectPackets();

  protected: // vars
    BDMAnalyzerSettings mSettings;
    std::unique_ptr<BDMAnalyzerResults> mResults;
    AnalyzerChannelData* mDSDI;
    AnalyzerChannelData* mDSDO;
    AnalyzerChannelData* mDSCK;
    AnalyzerChannelData* mHRESET;
    AnalyzerChannelData* mSRESET;
    AnalyzerChannelData* mVLFS0;
    AnalyzerChannelData* mVLFS1;

    BDMSimulationDataGenerator mSimulationDataGenerator;
    bool mSimulationInitilized;

    // Serial analysis vars:
    U32 mSampleRateHz;
    U32 mStartOfStopBitOffset;
    U32 mEndOfStopBitOffset;
    BDM_State bdm_state;
};


extern "C" ANALYZER_EXPORT const char* __cdecl GetAnalyzerName();
extern "C" ANALYZER_EXPORT Analyzer* __cdecl CreateAnalyzer();
extern "C" ANALYZER_EXPORT void __cdecl DestroyAnalyzer( Analyzer* analyzer );

#endif // BDM_ANALYZER_H
