#include "BDMAnalyzerSettings.h"
#include <AnalyzerHelpers.h>


BDMAnalyzerSettings::BDMAnalyzerSettings()
    : mDSDIChannel( UNDEFINED_CHANNEL ),
      mDSDOChannel( UNDEFINED_CHANNEL ),
      mDSCKChannel( UNDEFINED_CHANNEL ),
      mHRESETChannel( UNDEFINED_CHANNEL ),
      mSRESETChannel( UNDEFINED_CHANNEL ),
      mVFLS0Channel( UNDEFINED_CHANNEL ),
      mVFLS1Channel( UNDEFINED_CHANNEL ),
      mBitRate( 1000000 ),
      mDSDIChannelInterface(),
      mDSDOChannelInterface(),
      mDSCKChannelInterface(),
      mHRESETChannelInterface(),
      mSRESETChannelInterface(),
      mVFLS0ChannelInterface(),
      mVFLS1ChannelInterface(),
      mBitRateInterface()
{
    mDSDIChannelInterface.SetTitleAndTooltip( "DSDI", "Standard BDM" );
    mDSDIChannelInterface.SetChannel( mDSDIChannel );

    mDSDOChannelInterface.SetTitleAndTooltip( "DSDO", "Standard BDM" );
    mDSDOChannelInterface.SetChannel( mDSDOChannel );

    mDSCKChannelInterface.SetTitleAndTooltip( "DSCK", "Standard BDM" );
    mDSCKChannelInterface.SetChannel( mDSCKChannel );

    mHRESETChannelInterface.SetTitleAndTooltip( "HRESET", "Standard BDM" );
    mHRESETChannelInterface.SetChannel( mHRESETChannel );

    mSRESETChannelInterface.SetTitleAndTooltip( "SRESET", "Standard BDM" );
    mSRESETChannelInterface.SetChannel( mSRESETChannel );

    mVFLS0ChannelInterface.SetTitleAndTooltip( "VLFS0", "Standard BDM" );
    mVFLS0ChannelInterface.SetChannel( mVFLS0Channel );

    mVFLS1ChannelInterface.SetTitleAndTooltip( "VLFS1", "Standard BDM" );
    mVFLS1ChannelInterface.SetChannel( mVFLS1Channel );

    mBitRateInterface.SetTitleAndTooltip( "Bit Rate (Bits/S)", "Specify the bit rate in bits per second." );
    mBitRateInterface.SetMax( 6000000 );
    mBitRateInterface.SetMin( 1 );
    mBitRateInterface.SetInteger( mBitRate );

    AddInterface( &mDSDIChannelInterface );
    AddInterface( &mDSDOChannelInterface );
    AddInterface( &mDSCKChannelInterface );
    AddInterface( &mHRESETChannelInterface );
    AddInterface( &mSRESETChannelInterface );
    AddInterface( &mVFLS0ChannelInterface );
    AddInterface( &mVFLS1ChannelInterface );

    AddInterface( &mBitRateInterface );

    AddExportOption( 0, "Export as text/csv file" );
    AddExportExtension( 0, "text", "txt" );
    AddExportExtension( 0, "csv", "csv" );

    ClearChannels();
    AddChannel( mDSDIChannel, "DSDI", false );
    AddChannel( mDSDOChannel, "DSDO", false );
    AddChannel( mDSCKChannel, "DSCK", false );
    AddChannel( mHRESETChannel, "HRESET", false );
    AddChannel( mSRESETChannel, "SRESET", false );
    AddChannel( mVFLS0Channel, "VLFS0", false );
    AddChannel( mVFLS1Channel, "VLFS1", false );
}

BDMAnalyzerSettings::~BDMAnalyzerSettings()
{
}

bool BDMAnalyzerSettings::SetSettingsFromInterfaces()
{
    mDSDIChannel = mDSDIChannelInterface.GetChannel();
    mDSDOChannel = mDSDOChannelInterface.GetChannel();
    mDSCKChannel = mDSCKChannelInterface.GetChannel();
    mHRESETChannel = mHRESETChannelInterface.GetChannel();
    mSRESETChannel = mSRESETChannelInterface.GetChannel();
    mVFLS0Channel = mVFLS0ChannelInterface.GetChannel();
    mVFLS1Channel = mVFLS1ChannelInterface.GetChannel();
    mBitRate = mBitRateInterface.GetInteger();

    ClearChannels();
    AddChannel( mDSDIChannel, "BDM", true );
    AddChannel( mDSDOChannel, "BDM", true );
    AddChannel( mDSCKChannel, "BDM", true );
    AddChannel( mHRESETChannel, "BDM", true );
    AddChannel( mSRESETChannel, "BDM", true );
    AddChannel( mVFLS0Channel, "BDM", true );
    AddChannel( mVFLS1Channel, "BDM", true );
    AddChannel( mDSDIChannel, "BDM", true );
    AddChannel( mDSDIChannel, "BDM", true );

    return true;
}

void BDMAnalyzerSettings::UpdateInterfacesFromSettings()
{
    mDSDIChannelInterface.SetChannel( mDSDIChannel );
    mDSDOChannelInterface.SetChannel( mDSDOChannel );
    mBitRateInterface.SetInteger( mBitRate );
}

void BDMAnalyzerSettings::LoadSettings( const char* settings )
{
    SimpleArchive text_archive;
    text_archive.SetString( settings );

    // text_archive >> mInputChannel;
    text_archive >> mBitRate;

    ClearChannels();
    AddChannel( mDSDIChannel, "BDM", true );
    AddChannel( mDSDOChannel, "BDM", true );

    UpdateInterfacesFromSettings();
}

const char* BDMAnalyzerSettings::SaveSettings()
{
    SimpleArchive text_archive;

    // text_archive << mInputChannel;
    text_archive << mDSDIChannel;
    text_archive << mDSDOChannel;
    text_archive << mBitRate;

    return SetReturnString( text_archive.GetString() );
}
