#ifndef BDM_ANALYZER_SETTINGS
#define BDM_ANALYZER_SETTINGS

#include <AnalyzerSettings.h>
#include <AnalyzerTypes.h>

class BDMAnalyzerSettings : public AnalyzerSettings
{
  public:
    BDMAnalyzerSettings();
    virtual ~BDMAnalyzerSettings();

    virtual bool SetSettingsFromInterfaces();
    void UpdateInterfacesFromSettings();
    virtual void LoadSettings( const char* settings );
    virtual const char* SaveSettings();


    Channel mDSDIChannel;
    Channel mDSDOChannel;
    Channel mDSCKChannel;
    Channel mHRESETChannel;
    Channel mSRESETChannel;
    Channel mVFLS0Channel;
    Channel mVFLS1Channel;
    U32 mBitRate;

  protected:
    AnalyzerSettingInterfaceChannel mDSDIChannelInterface;
    AnalyzerSettingInterfaceChannel mDSDOChannelInterface;
    AnalyzerSettingInterfaceChannel mDSCKChannelInterface;
    AnalyzerSettingInterfaceChannel mHRESETChannelInterface;
    AnalyzerSettingInterfaceChannel mSRESETChannelInterface;
    AnalyzerSettingInterfaceChannel mVFLS0ChannelInterface;
    AnalyzerSettingInterfaceChannel mVFLS1ChannelInterface;
    AnalyzerSettingInterfaceInteger mBitRateInterface;
};

#endif // BDM_ANALYZER_SETTINGS
