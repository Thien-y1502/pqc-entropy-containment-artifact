// SPDX-License-Identifier: MIT
// Bounded P01 confirmation worker. Controlled software entropy experiment only.

#include <oqs/oqs.h>
#include "sha3.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t rng_seed[32];
static uint64_t rng_call;

struct component_result {
    char ciphertext_digest[65];
    char shared_secret_digest[65];
    bool honest_agreement;
};

struct trial_result {
    uint64_t trial;
    struct component_result mlkem;
    struct component_result hqc;
    char hybrid_ciphertext_digest[65];
    char hybrid_shared_secret_digest[65];
    bool honest_agreement;
};

struct recipient {
    OQS_KEM *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
};

static void u64le(uint8_t out[8], uint64_t value) {
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t) (value >> (8 * i));
    }
}

static void controlled_randombytes(uint8_t *out, size_t outlen) {
    uint8_t input[48];
    uint8_t call_bytes[8];
    uint8_t length_bytes[8];
    memcpy(input, rng_seed, sizeof(rng_seed));
    u64le(call_bytes, rng_call++);
    u64le(length_bytes, (uint64_t) outlen);
    memcpy(input + 32, call_bytes, 8);
    memcpy(input + 40, length_bytes, 8);
    OQS_SHA3_shake256(out, outlen, input, sizeof(input));
    OQS_MEM_cleanse(input, sizeof(input));
}

static void set_rng(const uint8_t seed[32]) {
    memcpy(rng_seed, seed, sizeof(rng_seed));
    rng_call = 0;
}

static void digest_hex(const uint8_t *input, size_t input_len, char output[65]) {
    uint8_t digest[32];
    static const char alphabet[] = "0123456789abcdef";
    OQS_SHA3_shake256(digest, sizeof(digest), input, input_len);
    for (size_t i = 0; i < sizeof(digest); i++) {
        output[i * 2] = alphabet[digest[i] >> 4];
        output[i * 2 + 1] = alphabet[digest[i] & 0x0f];
    }
    output[64] = '\0';
    OQS_MEM_cleanse(digest, sizeof(digest));
}

static bool known(const char *value, const char *const *items, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(value, items[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void derive_seed(const char *architecture, const char *recipe,
                        const char *component, uint64_t trial, uint8_t out[32]) {
    bool event = strcmp(recipe, "nominal") != 0;
    bool context_reset = strcmp(recipe, "origin_rng_and_context_reuse") == 0;
    uint64_t raw_index = trial;
    uint64_t context_index = 0;
    const char *domain = "shared";

    if (strcmp(architecture, "A0_SHARED") == 0) {
        raw_index = event ? 0 : trial;
    } else if (strcmp(architecture, "A1_LABEL_ONLY") == 0) {
        domain = component;
        raw_index = event ? 0 : trial;
    } else if (strcmp(architecture, "A2_GLOBAL_SPLIT_SHAM") == 0) {
        domain = "reached-caller-interface";
        raw_index = event ? 0 : trial;
    } else if (strcmp(architecture, "A3_ROLE_ROUTED") == 0) {
        domain = component;
        if (event && strcmp(component, "ML-KEM-768") == 0) {
            raw_index = 0;
        }
    } else if (strcmp(architecture, "A4_HEDGED") == 0) {
        domain = component;
        raw_index = event ? 0 : trial;
        context_index = context_reset ? 0 : trial;
    }

    char material[256];
    int length = snprintf(material, sizeof(material),
                          "P01-LIBOQS-V1|%s|%s|raw=%llu|context=%llu|protected=%s",
                          architecture, domain,
                          (unsigned long long) raw_index,
                          (unsigned long long) context_index,
                          strcmp(architecture, "A4_HEDGED") == 0 ? component : "none");
    if (length < 0 || (size_t) length >= sizeof(material)) {
        fprintf(stderr, "seed material overflow\n");
        exit(EXIT_FAILURE);
    }
    OQS_SHA3_shake256(out, 32, (const uint8_t *) material, (size_t) length);
    OQS_MEM_cleanse(material, sizeof(material));
}

static bool recipient_init(struct recipient *recipient, const char *algorithm) {
    memset(recipient, 0, sizeof(*recipient));
    recipient->kem = OQS_KEM_new(algorithm);
    if (recipient->kem == NULL) {
        return false;
    }
    recipient->public_key = OQS_MEM_malloc(recipient->kem->length_public_key);
    recipient->secret_key = OQS_MEM_malloc(recipient->kem->length_secret_key);
    if (recipient->public_key == NULL || recipient->secret_key == NULL) {
        return false;
    }
    uint8_t seed[32];
    char label[128];
    int length = snprintf(label, sizeof(label), "P01-RECIPIENT-V1|%s", algorithm);
    if (length < 0 || (size_t) length >= sizeof(label)) {
        return false;
    }
    OQS_SHA3_shake256(seed, sizeof(seed), (const uint8_t *) label, (size_t) length);
    set_rng(seed);
    OQS_MEM_cleanse(seed, sizeof(seed));
    OQS_MEM_cleanse(label, sizeof(label));
    return OQS_KEM_keypair(recipient->kem, recipient->public_key, recipient->secret_key) == OQS_SUCCESS;
}

static void recipient_free(struct recipient *recipient) {
    if (recipient->kem != NULL) {
        OQS_MEM_insecure_free(recipient->public_key);
        OQS_MEM_secure_free(recipient->secret_key, recipient->kem->length_secret_key);
        OQS_KEM_free(recipient->kem);
    }
    memset(recipient, 0, sizeof(*recipient));
}

static bool encapsulate(const struct recipient *recipient, const uint8_t seed[32],
                        struct component_result *result, uint8_t **ciphertext_out,
                        size_t *ciphertext_len, uint8_t **secret_out, size_t *secret_len) {
    uint8_t *ciphertext = OQS_MEM_malloc(recipient->kem->length_ciphertext);
    uint8_t *shared = OQS_MEM_malloc(recipient->kem->length_shared_secret);
    uint8_t *received = OQS_MEM_malloc(recipient->kem->length_shared_secret);
    if (ciphertext == NULL || shared == NULL || received == NULL) {
        OQS_MEM_insecure_free(ciphertext);
        OQS_MEM_insecure_free(shared);
        OQS_MEM_insecure_free(received);
        return false;
    }
    set_rng(seed);
    OQS_STATUS enc = OQS_KEM_encaps(recipient->kem, ciphertext, shared, recipient->public_key);
    OQS_STATUS dec = enc == OQS_SUCCESS
                         ? OQS_KEM_decaps(recipient->kem, received, ciphertext, recipient->secret_key)
                         : OQS_ERROR;
    result->honest_agreement = enc == OQS_SUCCESS && dec == OQS_SUCCESS &&
                               memcmp(shared, received, recipient->kem->length_shared_secret) == 0;
    digest_hex(ciphertext, recipient->kem->length_ciphertext, result->ciphertext_digest);
    digest_hex(shared, recipient->kem->length_shared_secret, result->shared_secret_digest);
    OQS_MEM_cleanse(received, recipient->kem->length_shared_secret);
    OQS_MEM_insecure_free(received);
    *ciphertext_out = ciphertext;
    *ciphertext_len = recipient->kem->length_ciphertext;
    *secret_out = shared;
    *secret_len = recipient->kem->length_shared_secret;
    return result->honest_agreement;
}

static bool run_trial(const struct recipient *mlkem, const struct recipient *hqc,
                      const char *architecture, const char *recipe, uint64_t trial,
                      struct trial_result *result) {
    memset(result, 0, sizeof(*result));
    result->trial = trial;
    uint8_t mlkem_seed[32], hqc_seed[32];
    uint8_t *mlkem_ct = NULL, *hqc_ct = NULL, *mlkem_ss = NULL, *hqc_ss = NULL;
    size_t mlkem_ct_len = 0, hqc_ct_len = 0, mlkem_ss_len = 0, hqc_ss_len = 0;
    derive_seed(architecture, recipe, "ML-KEM-768", trial, mlkem_seed);
    derive_seed(architecture, recipe, "HQC-3", trial, hqc_seed);
    bool ok = encapsulate(mlkem, mlkem_seed, &result->mlkem, &mlkem_ct, &mlkem_ct_len,
                          &mlkem_ss, &mlkem_ss_len) &&
              encapsulate(hqc, hqc_seed, &result->hqc, &hqc_ct, &hqc_ct_len,
                          &hqc_ss, &hqc_ss_len);
    OQS_MEM_cleanse(mlkem_seed, sizeof(mlkem_seed));
    OQS_MEM_cleanse(hqc_seed, sizeof(hqc_seed));
    if (!ok) {
        OQS_MEM_insecure_free(mlkem_ct);
        OQS_MEM_insecure_free(hqc_ct);
        OQS_MEM_secure_free(mlkem_ss, mlkem_ss_len);
        OQS_MEM_secure_free(hqc_ss, hqc_ss_len);
        return false;
    }
    uint8_t *combined_ct = OQS_MEM_malloc(mlkem_ct_len + hqc_ct_len);
    uint8_t *combined_ss = OQS_MEM_malloc(mlkem_ss_len + hqc_ss_len);
    if (combined_ct == NULL || combined_ss == NULL) {
        return false;
    }
    memcpy(combined_ct, mlkem_ct, mlkem_ct_len);
    memcpy(combined_ct + mlkem_ct_len, hqc_ct, hqc_ct_len);
    memcpy(combined_ss, mlkem_ss, mlkem_ss_len);
    memcpy(combined_ss + mlkem_ss_len, hqc_ss, hqc_ss_len);
    digest_hex(combined_ct, mlkem_ct_len + hqc_ct_len, result->hybrid_ciphertext_digest);
    digest_hex(combined_ss, mlkem_ss_len + hqc_ss_len, result->hybrid_shared_secret_digest);
    result->honest_agreement = result->mlkem.honest_agreement && result->hqc.honest_agreement;
    OQS_MEM_insecure_free(mlkem_ct);
    OQS_MEM_insecure_free(hqc_ct);
    OQS_MEM_secure_free(mlkem_ss, mlkem_ss_len);
    OQS_MEM_secure_free(hqc_ss, hqc_ss_len);
    OQS_MEM_insecure_free(combined_ct);
    OQS_MEM_secure_free(combined_ss, mlkem_ss_len + hqc_ss_len);
    return result->honest_agreement;
}

static void print_trial(const struct trial_result *result) {
    printf("{\"trial\":%llu,", (unsigned long long) result->trial);
    printf("\"mlkem_ciphertext_shake256_32\":\"%s\",", result->mlkem.ciphertext_digest);
    printf("\"hqc_ciphertext_shake256_32\":\"%s\",", result->hqc.ciphertext_digest);
    printf("\"hybrid_ciphertext_shake256_32\":\"%s\",", result->hybrid_ciphertext_digest);
    printf("\"hybrid_shared_secret_shake256_32\":\"%s\",", result->hybrid_shared_secret_digest);
    printf("\"honest_agreement\":%s}", result->honest_agreement ? "true" : "false");
}

int main(int argc, char **argv) {
    const char *architecture = NULL;
    const char *recipe = NULL;
    uint64_t anchor_trial = 0, comparison_trial = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--unit-architecture") == 0 && i + 1 < argc) {
            architecture = argv[++i];
        } else if (strcmp(argv[i], "--unit-recipe") == 0 && i + 1 < argc) {
            recipe = argv[++i];
        } else if (strcmp(argv[i], "--unit-anchor") == 0 && i + 1 < argc) {
            anchor_trial = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--unit-trial") == 0 && i + 1 < argc) {
            comparison_trial = strtoull(argv[++i], NULL, 10);
        } else {
            fprintf(stderr, "invalid argument\n");
            return EXIT_FAILURE;
        }
    }
    const char *const architectures[] = {"A0_SHARED", "A1_LABEL_ONLY", "A2_GLOBAL_SPLIT_SHAM",
                                          "A3_ROLE_ROUTED", "A4_HEDGED"};
    const char *const recipes[] = {"nominal", "origin_rng_state_reuse",
                                    "origin_rng_and_context_reuse"};
    if (architecture == NULL || recipe == NULL || comparison_trial == 0 ||
        !known(architecture, architectures, 5) || !known(recipe, recipes, 3)) {
        fprintf(stderr, "invalid pair configuration\n");
        return EXIT_FAILURE;
    }

    OQS_init();
    OQS_randombytes_custom_algorithm(controlled_randombytes);
    struct recipient mlkem, hqc;
    if (!recipient_init(&mlkem, OQS_KEM_alg_ml_kem_768) ||
        !recipient_init(&hqc, OQS_KEM_alg_hqc_3)) {
        fprintf(stderr, "recipient initialization failed\n");
        recipient_free(&mlkem);
        recipient_free(&hqc);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    struct trial_result anchor, comparison;
    bool ok = run_trial(&mlkem, &hqc, architecture, recipe, anchor_trial, &anchor) &&
              run_trial(&mlkem, &hqc, architecture, recipe, comparison_trial, &comparison);
    if (!ok) {
        fprintf(stderr, "KEM agreement failed\n");
        recipient_free(&mlkem);
        recipient_free(&hqc);
        OQS_destroy();
        return EXIT_FAILURE;
    }
    bool mlkem_fresh = strcmp(anchor.mlkem.ciphertext_digest, comparison.mlkem.ciphertext_digest) != 0;
    bool hqc_fresh = strcmp(anchor.hqc.ciphertext_digest, comparison.hqc.ciphertext_digest) != 0;
    bool hybrid_fresh = strcmp(anchor.hybrid_ciphertext_digest, comparison.hybrid_ciphertext_digest) != 0;
    printf("{\"schema_version\":\"1.0\",\"implementation\":\"liboqs-dual-pqc\",");
    printf("\"liboqs_commit\":\"5a1a854b0dc9f2141bdc771c555ee60c37950183\",");
    printf("\"architecture\":\"%s\",\"recipe\":\"%s\",", architecture, recipe);
    printf("\"anchor\":"); print_trial(&anchor);
    printf(",\"comparison\":"); print_trial(&comparison);
    printf(",\"mlkem_freshness_preserved\":%s", mlkem_fresh ? "true" : "false");
    printf(",\"hqc_freshness_preserved\":%s", hqc_fresh ? "true" : "false");
    printf(",\"peer_freshness_preserved\":%s", hqc_fresh ? "true" : "false");
    printf(",\"hybrid_freshness_preserved\":%s}\n", hybrid_fresh ? "true" : "false");
    recipient_free(&mlkem);
    recipient_free(&hqc);
    OQS_MEM_cleanse(rng_seed, sizeof(rng_seed));
    OQS_destroy();
    return EXIT_SUCCESS;
}
