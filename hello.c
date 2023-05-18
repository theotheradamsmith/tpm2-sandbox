#include <stdio.h>
#include <string.h>
#include <tss2/tss2_fapi.h>

int main() {
    TSS2_RC r = 0;
    char *err = NULL;

    // Initialize the FAPI Context
    FAPI_CONTEXT *fapi_context;
    r = Fapi_Initialize(&fapi_context, NULL);
    if (r != TSS2_RC_SUCCESS) {
        err = "Failed to initialize";
        goto error;
    }

    char *info = NULL;
    r = Fapi_GetInfo(fapi_context, &info);
    if (r != TSS2_RC_SUCCESS) {
        err = "Failed to get info";
        goto error;
    }

    printf("TPM Info: \n%s\n", info);
    Fapi_Free(info);

    r = Fapi_Provision(fapi_context, NULL, NULL, NULL);
    if (r == TSS2_FAPI_RC_ALREADY_PROVISIONED) {
        fprintf(stderr, "Already provisioned! 0x%x", r);
    } else if (r != TSS2_RC_SUCCESS) {
        err = "Failed to provision";
        goto error;
    }

    Fapi_Finalize(&fapi_context);
    return 0;

error:
    fprintf(stderr, "Error 0x%x: %s", r, err);
    Fapi_Finalize(&fapi_context);
    return 1;
}