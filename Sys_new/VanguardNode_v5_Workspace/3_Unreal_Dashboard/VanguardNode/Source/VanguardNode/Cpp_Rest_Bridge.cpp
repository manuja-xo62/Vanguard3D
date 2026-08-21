#include "Cpp_Rest_Bridge.h"
#include "JsonObjectConverter.h"
#include "Serialization/JsonSerializer.h"

void UCpp_Rest_Bridge::FetchEvents()
{
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> Request = FHttpModule::Get().CreateRequest();

    Request->SetURL("http://127.0.0.1:8000/api/scan");
    Request->SetVerb("POST");
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Pass the required scan target path payload
    FString Payload = TEXT("{\"target_path\": \"../sample_repo\"}");
    Request->SetContentAsString(Payload);

    Request->OnProcessRequestComplete().BindUObject(this, &UCpp_Rest_Bridge::OnFetchComplete);
    Request->ProcessRequest();
}

void UCpp_Rest_Bridge::OnFetchComplete(FHttpRequestPtr Request, FHttpResponsePtr Response, bool bWasSuccessful)
{
    if (bWasSuccessful && Response.IsValid())
    {
        UE_LOG(LogTemp, Warning, TEXT("[Vanguard] HTTP %d Response: %s"), Response->GetResponseCode(), *Response->GetContentAsString());
        OnEventsFetched.Broadcast(Response->GetContentAsString());
    }
    else
    {
        UE_LOG(LogTemp, Error, TEXT("[Vanguard] HTTP Request Failed completely."));
        OnEventsFetched.Broadcast(TEXT("{\"error\": \"CONNECTION_FAILED\"}"));
    }
}

void UCpp_Rest_Bridge::ApplyPatch(const FString& FindingID)
{
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> Request = FHttpModule::Get().CreateRequest();
    Request->SetURL("http://127.0.0.1:8000/api/patch");
    Request->SetVerb("POST");
    Request->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    FString Payload = FString::Printf(TEXT("{\"finding_id\": \"%s\"}"), *FindingID);
    Request->SetContentAsString(Payload);

    Request->OnProcessRequestComplete().BindUObject(this, &UCpp_Rest_Bridge::OnPatchComplete);
    Request->ProcessRequest();
}

void UCpp_Rest_Bridge::OnPatchComplete(FHttpRequestPtr Request, FHttpResponsePtr Response, bool bWasSuccessful)
{
    if (bWasSuccessful && Response.IsValid())
    {
        OnPatchApplied.Broadcast(Response->GetContentAsString());
    }
}

bool UCpp_Rest_Bridge::ParseScanJson(const FString& JsonString, FScanResponse& OutScanData)
{
    OutScanData = FScanResponse();

    if (JsonString.IsEmpty() || JsonString.Contains(TEXT("CONNECTION_FAILED")))
    {
        return false;
    }

    TSharedPtr<FJsonObject> TargetScanObject;

    // Case 1: JsonString is a Single Scan Object {...}
    TSharedPtr<FJsonObject> DirectObject;
    TSharedRef<TJsonReader<>> DirectReader = TJsonReaderFactory<>::Create(JsonString);
    if (FJsonSerializer::Deserialize(DirectReader, DirectObject) && DirectObject.IsValid())
    {
        TargetScanObject = DirectObject;
    }
    // Case 2: JsonString is a Scan History Array [{...}, {...}] -> Extract LATEST scan record
    else
    {
        TArray<TSharedPtr<FJsonValue>> JsonArray;
        TSharedRef<TJsonReader<>> ArrayReader = TJsonReaderFactory<>::Create(JsonString);
        if (FJsonSerializer::Deserialize(ArrayReader, JsonArray) && JsonArray.Num() > 0)
        {
            TargetScanObject = JsonArray.Last()->AsObject();
        }
    }

    // Convert only the latest scan object into the FScanResponse struct
    if (TargetScanObject.IsValid())
    {
        return FJsonObjectConverter::JsonObjectToUStruct(TargetScanObject.ToSharedRef(), &OutScanData, 0, 0);
    }

    return false;
}