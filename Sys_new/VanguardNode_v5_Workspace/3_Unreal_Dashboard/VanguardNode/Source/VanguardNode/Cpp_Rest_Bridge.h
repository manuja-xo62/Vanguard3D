#pragma once

#include "CoreMinimal.h"
#include "UObject/NoExportTypes.h"
#include "Http.h"
#include "Cpp_Rest_Bridge.generated.h"

USTRUCT(BlueprintType)
struct FSingleFinding
{
    GENERATED_BODY()

        UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FString finding_id;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FString rule_id;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FString rule_title;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FString severity;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FString file_path;
};

USTRUCT(BlueprintType)
struct FFileFinding
{
    GENERATED_BODY()

        UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FString file_path;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        int32 findings_count = 0;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        float R_file = 0.0f;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        int32 file_criticality = 0;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        TArray<FSingleFinding> findings;
};

USTRUCT(BlueprintType)
struct FScanDataWrapper
{
    GENERATED_BODY()

        UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        float R_global = 0.0f;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        TArray<FFileFinding> files;
};

USTRUCT(BlueprintType)
struct FScanResponse
{
    GENERATED_BODY()

        UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FString status;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FString scan_id;

    UPROPERTY(BlueprintReadWrite, EditAnywhere, Category = "Vanguard")
        FScanDataWrapper data;
};

DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FOnDataReceived, const FString&, JsonResponse);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FOnScanParsed, const FScanResponse&, ScanData);

UCLASS(Blueprintable, BlueprintType)
class VANGUARDNODE_API UCpp_Rest_Bridge : public UObject
{
    GENERATED_BODY()

public:
    UFUNCTION(BlueprintCallable, Category = "Vanguard|Network")
        void FetchEvents();

    UFUNCTION(BlueprintCallable, Category = "Vanguard|Network")
        void ApplyPatch(const FString& FindingID);

    UFUNCTION(BlueprintCallable, Category = "Vanguard|Parser")
        static bool ParseScanJson(const FString& JsonString, FScanResponse& OutScanData);

    UPROPERTY(BlueprintAssignable, Category = "Vanguard|Network")
        FOnDataReceived OnEventsFetched;

    UPROPERTY(BlueprintAssignable, Category = "Vanguard|Network")
        FOnDataReceived OnPatchApplied;

    UPROPERTY(BlueprintAssignable, Category = "Vanguard|Network")
        FOnScanParsed OnScanParsed;

private:
    void OnFetchComplete(FHttpRequestPtr Request, FHttpResponsePtr Response, bool bWasSuccessful);
    void OnPatchComplete(FHttpRequestPtr Request, FHttpResponsePtr Response, bool bWasSuccessful);
};