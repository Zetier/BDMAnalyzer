#include "BDMAnalyzerResults.h"
#include <AnalyzerHelpers.h>
#include "BDMAnalyzer.h"
#include "BDMAnalyzerSettings.h"
#include <iostream>
#include <fstream>

BDMAnalyzerResults::BDMAnalyzerResults( BDMAnalyzer* analyzer, BDMAnalyzerSettings* settings )
    : AnalyzerResults(), mSettings( settings ), mAnalyzer( analyzer )
{
}

BDMAnalyzerResults::~BDMAnalyzerResults()
{
}

void BDMAnalyzerResults::GenerateBubbleText( U64 frame_index, Channel& channel, DisplayBase display_base )
{
    ClearResultStrings();
    Frame frame = GetFrame( frame_index );

    if( channel == mSettings->mDSDIChannel )
    {
        char number_str[ 128 ];
        AnalyzerHelpers::GetNumberString( frame.mData1, display_base, 8, number_str, 128 );
        AddResultString( number_str );
    }
    else if( channel == mSettings->mDSDOChannel )
    {
        char number_str[ 128 ];
        AnalyzerHelpers::GetNumberString( frame.mData2, display_base, 8, number_str, 128 );
        AddResultString( number_str );
    }
}

void BDMAnalyzerResults::GenerateExportFile( const char* file, DisplayBase display_base, U32 export_type_user_id )
{
    std::ofstream file_stream( file, std::ios::out );

    U64 trigger_sample = mAnalyzer->GetTriggerSample();
    U32 sample_rate = mAnalyzer->GetSampleRate();

    file_stream << "Time [s],Value" << std::endl;

    U64 num_frames = GetNumFrames();
    for( U32 i = 0; i < num_frames; i++ )
    {
        Frame frame = GetFrame( i );

        char time_str[ 128 ];
        AnalyzerHelpers::GetTimeString( frame.mStartingSampleInclusive, trigger_sample, sample_rate, time_str, 128 );

        char number_str[ 128 ];
        AnalyzerHelpers::GetNumberString( frame.mData1, display_base, 8, number_str, 128 );

        file_stream << time_str << "," << number_str << std::endl;

        if( UpdateExportProgressAndCheckForCancel( i, num_frames ) == true )
        {
            file_stream.close();
            return;
        }
    }

    file_stream.close();
}

void BDMAnalyzerResults::GenerateFrameTabularText( U64 frame_index, DisplayBase display_base )
{
#ifdef SUPPORTS_PROTOCOL_SEARCH
    Frame frame = GetFrame( frame_index );
    ClearTabularText();

    char number_str[ 128 ];
    AnalyzerHelpers::GetNumberString( frame.mData1, display_base, 8, number_str, 128 );
    AddTabularText( number_str );
#endif
}

void BDMAnalyzerResults::GeneratePacketTabularText( U64 packet_id, DisplayBase display_base )
{
    // not supported
}

void BDMAnalyzerResults::GenerateTransactionTabularText( U64 transaction_id, DisplayBase display_base )
{
    // not supported
}
