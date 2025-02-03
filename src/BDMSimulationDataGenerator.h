#ifndef BDM_SIMULATION_DATA_GENERATOR
#define BDM_SIMULATION_DATA_GENERATOR

#include <SimulationChannelDescriptor.h>
#include <string>
class BDMAnalyzerSettings;

class BDMSimulationDataGenerator
{
  public:
    BDMSimulationDataGenerator();
    ~BDMSimulationDataGenerator();

    void Initialize( U32 simulation_sample_rate, BDMAnalyzerSettings* settings );
    U32 GenerateSimulationData( U64 newest_sample_requested, U32 sample_rate, SimulationChannelDescriptor** simulation_channel );

  protected:
    BDMAnalyzerSettings* mSettings;
    U32 mSimulationSampleRateHz;

  protected:
    void CreateSerialByte();
    std::string mSerialText;
    U32 mStringIndex;

    SimulationChannelDescriptor mSerialSimulationData;
};
#endif // BDM_SIMULATION_DATA_GENERATOR