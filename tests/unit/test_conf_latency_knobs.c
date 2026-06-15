/*
 * Standalone unit test for the latency-weighted-read config knobs and the
 * zone_weight deprecation (Task 5 of the latency-weighted-reads plan).
 *
 * Twemproxy has no C unit-test framework (tests/ is Python integration that
 * needs a live redis). This is a freestanding C test that links the real
 * nc_conf.c + nc_server.c objects and drives the REAL parse pipeline
 * (conf_create -> conf_pool_each_transform via server_pool_init) against a
 * temp YAML file, so we exercise production parsing + the conf->server_pool
 * transform without a network.
 *
 * What it proves
 * --------------
 *   1. A pool that sets cross_az_surcharge_us + latency_band_factor parses
 *      into the matching server_pool fields (the transform reads conf_pool,
 *      not a hardcoded default).
 *   2. A pool that OMITS both keys gets the CONF_DEFAULT_* values.
 *   3. latency_band_factor: 0 parses (it is a legal uint -- "keep all"); the
 *      transform passes the 0 through.
 *   4. A pool that sets zone_weight emits a one-time DEPRECATION warning during
 *      conf validation (captured by redirecting stderr to a temp file and
 *      grepping for "deprecat"); a config that never sets zone_weight does NOT
 *      emit it.
 *
 * All pools use dynamic_endpoint:false so server_pool_init's transform stays
 * offline (a dynamic pool would call server_dns_init -> real DNS resolution;
 * the knob parsing -- the thing Task 5 adds -- is fully captured by a static
 * pool, mirroring how test_dynamic_endpoint drives the predicate directly).
 *
 * Red->green
 * ----------
 * This test stages its red TWO ways (both shown when implementing Task 5):
 *
 *   1. Against the PRE-Task-5 tree (before nc_conf.c is patched), the DEFAULT
 *      build fails outright: cross_az_surcharge_us / latency_band_factor are not
 *      yet in the keyword table so conf_create rejects them ("directive ... is
 *      unknown") and (1) cannot even parse; and the zone_weight deprecation
 *      warning does not exist yet so (4a) finds no "deprecat" -> red. This is
 *      the true behavioural red the task removes.
 *
 *   2. The -DTEST_PREFIX_NO_PARSE build is a COMPILE-TIME mirror that isolates
 *      the transform half: it lets the (now-patched) parser accept + validate
 *      the keys, then overwrites the two server_pool fields back to
 *      CONF_DEFAULT_* right after the transform -- exactly what the pre-Task-5
 *      transform did (it hardcoded the defaults regardless of config). Under it,
 *      (1)'s configured-non-default assertions fail -> non-zero exit, so
 *      run_nonzero records it as the staged red. (It does NOT suppress the
 *      deprecation warning -- that comes from the real conf_validate_pool, whose
 *      red is form (1) above -- so (4a) still passes here; the mirror's job is
 *      purely the transform-clobber red.) This mirrors how test_dynamic_endpoint
 *      (-DTEST_PREFIX_RO_AUTODETECT) and the others stage red builds in this
 *      suite.
 *
 * Build/run: see tests/unit/run.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include <nc_core.h>
#include <nc_conf.h>
#include <nc_server.h>
#include <nc_string.h>
#include <nc_log.h>
#include <nc.h>

/*
 * nc.c owns main() so it is excluded from the link; nc_signal.o references
 * nc_post_run() from there. A no-op stub satisfies the linker.
 */
void nc_post_run(struct instance *nci) { (void)nci; }

static int failures = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);              \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

/*
 * A minimal context with just enough zeroed state for server_pool_init to run
 * the transform. server_pool_init writes ctx->max_nsconn and iterates the
 * pools; the static-pool path needs nothing from the network.
 */
static struct context *
mk_ctx(void)
{
    struct context *ctx = nc_zalloc(sizeof(*ctx));
    ASSERT(ctx != NULL);
    ctx->id = 1;
    ctx->cf = NULL;
    array_null(&ctx->pool);
    ctx->max_timeout = 100;
    ctx->timeout = ctx->max_timeout;
    return ctx;
}

/* Write text to a fresh temp file; return a malloc'd path the caller frees. */
static char *
write_temp_conf(const char *text)
{
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || dir[0] == '\0') {
        dir = "/tmp";
    }
    char *path = nc_alloc(strlen(dir) + 32);
    ASSERT(path != NULL);
    sprintf(path, "%s/twem-conf-XXXXXX", dir);
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    ssize_t n = write(fd, text, strlen(text));
    ASSERT(n == (ssize_t)strlen(text));
    close(fd);
    return path;
}

/*
 * conf_parse() resolves the worker-drop user/group via getpwnam()/getgrnam() at
 * the end of parsing, even for a config that omits the "global:" section (it then
 * falls back to CONF_DEFAULT_USER / CONF_DEFAULT_GROUP, both "nobody"). That
 * default is RHEL-centric: Debian/Ubuntu have a "nobody" USER but no "nobody"
 * GROUP (they use "nogroup"), so getgrnam("nobody") returns NULL there and the
 * whole parse fails -- which has nothing to do with what this test checks (the
 * latency knobs + the zone_weight deprecation).
 *
 * Every real shipped config under conf/ declares an explicit "global:" section,
 * so prepend one here too, using the names of the user and group THIS PROCESS is
 * already running as. Those are guaranteed to resolve on whatever host runs the
 * test (Debian, RHEL, macOS, a container), making the test self-sufficient
 * instead of depending on which default privilege-drop accounts the OS ships.
 * Returns a malloc'd "global:\n...\npools:\n..." string the caller frees.
 */
static char *
with_global_header(const char *pools_text)
{
    struct passwd *pw = getpwuid(getuid());
    struct group  *gr = getgrgid(getgid());
    const char *user  = (pw != NULL && pw->pw_name != NULL) ? pw->pw_name : "root";
    const char *group = (gr != NULL && gr->gr_name != NULL) ? gr->gr_name : "root";

    static const char *fmt =
        "global:\n"
        "    user: %s\n"
        "    group: %s\n"
        "%s";
    int need = snprintf(NULL, 0, fmt, user, group, pools_text);
    ASSERT(need > 0);
    char *out = nc_alloc((size_t)need + 1);
    ASSERT(out != NULL);
    (void)snprintf(out, (size_t)need + 1, fmt, user, group, pools_text);
    return out;
}

#ifdef TEST_PREFIX_NO_PARSE
/*
 * Faithful mirror of the PRE-Task-5 world. Before Task 5, the conf_pool had no
 * cross_az_surcharge_us / latency_band_factor directive, so:
 *   (a) the transform ALWAYS wrote CONF_DEFAULT_* into the server_pool, no
 *       matter what (mirrored here by overwriting the two fields after the real
 *       transform runs), and
 *   (b) no deprecation warning existed for zone_weight (the real validate did
 *       not log one), mirrored by NOT inspecting the warning file.
 * Both mismatches are the TDD red below.
 */
static void
mirror_clobber_to_defaults(struct array *pools)
{
    uint32_t i;
    for (i = 0; i < array_n(pools); i++) {
        struct server_pool *sp = array_get(pools, i);
        sp->cross_az_surcharge_us = CONF_DEFAULT_CROSS_AZ_SURCHARGE_US;
        sp->latency_band_factor = CONF_DEFAULT_LATENCY_BAND_FACTOR;
    }
}
#endif

/*
 * Parse `text` and run the transform into a server_pool array. On success
 * returns the loaded conf (caller conf_destroy's it) and fills *out_pools.
 * Returns NULL on parse failure.
 */
static struct conf *
parse_and_transform(const char *text, struct context *ctx)
{
    /*
     * The CONF strings below carry only the "pools:" the test cares about; add a
     * "global:" header naming this process's own user/group so conf_parse()'s
     * privilege-drop lookup resolves on any host (see with_global_header()).
     */
    char *full = with_global_header(text);
    char *path = write_temp_conf(full);
    nc_free(full);
    struct conf *cf = conf_create(path);
    unlink(path);
    nc_free(path);
    if (cf == NULL) {
        return NULL;
    }
    ctx->cf = cf;
    rstatus_t status = server_pool_init(&ctx->pool, &cf->pool, ctx);
    if (status != NC_OK) {
        conf_destroy(cf);
        ctx->cf = NULL;
        return NULL;
    }
#ifdef TEST_PREFIX_NO_PARSE
    mirror_clobber_to_defaults(&ctx->pool);
#endif
    return cf;
}

static void
teardown(struct context *ctx, struct conf *cf)
{
    if (array_n(&ctx->pool) > 0) {
        server_pool_deinit(&ctx->pool);
    }
    if (cf != NULL) {
        conf_destroy(cf);
    }
    ctx->cf = NULL;
}

/* Find the pool named `name` in the transformed server_pool array. */
static struct server_pool *
find_pool(struct array *pools, const char *name)
{
    uint32_t i;
    for (i = 0; i < array_n(pools); i++) {
        struct server_pool *sp = array_get(pools, i);
        if (sp->name.len == strlen(name) &&
            memcmp(sp->name.data, name, sp->name.len) == 0) {
            return sp;
        }
    }
    return NULL;
}

/*
 * (1)+(2)+(3): the two knobs parse onto the right server_pool, omitted keys
 * default, and latency_band_factor:0 passes through.
 */
static void
test_knobs_parse_and_default(void)
{
    /*
     * pool "set" sets both knobs to non-default values; pool "deflt" omits them
     * (must take CONF_DEFAULT_*); pool "bandzero" sets band 0 (legal uint).
     * All static (dynamic_endpoint:false) so the transform stays offline.
     */
    static const char *CONF =
        "pools:\n"
        "    set:\n"
        "        listen: 127.0.0.1:11201\n"
        "        redis: true\n"
        "        dynamic_endpoint: false\n"
        "        cross_az_surcharge_us: 250\n"
        "        latency_band_factor: 5\n"
        "        servers:\n"
        "            - 127.0.0.1:6401:1\n"
        "    deflt:\n"
        "        listen: 127.0.0.1:11202\n"
        "        redis: true\n"
        "        dynamic_endpoint: false\n"
        "        servers:\n"
        "            - 127.0.0.1:6402:1\n"
        "    bandzero:\n"
        "        listen: 127.0.0.1:11203\n"
        "        redis: true\n"
        "        dynamic_endpoint: false\n"
        "        latency_band_factor: 0\n"
        "        servers:\n"
        "            - 127.0.0.1:6403:1\n";

    struct context *ctx = mk_ctx();
    struct conf *cf = parse_and_transform(CONF, ctx);
    CHECK(cf != NULL, "config with the new knobs must parse");
    if (cf == NULL) { nc_free(ctx); return; }

    struct server_pool *set = find_pool(&ctx->pool, "set");
    struct server_pool *deflt = find_pool(&ctx->pool, "deflt");
    struct server_pool *bz = find_pool(&ctx->pool, "bandzero");
    CHECK(set != NULL && deflt != NULL && bz != NULL, "all three pools present");

    if (set != NULL) {
        CHECK(set->cross_az_surcharge_us == 250,
              "cross_az_surcharge_us must parse to 250, got %"PRIu32,
              set->cross_az_surcharge_us);
        CHECK(set->latency_band_factor == 5,
              "latency_band_factor must parse to 5, got %"PRIu32,
              set->latency_band_factor);
    }
    if (deflt != NULL) {
        CHECK(deflt->cross_az_surcharge_us == CONF_DEFAULT_CROSS_AZ_SURCHARGE_US,
              "omitted cross_az_surcharge_us must default to %u, got %"PRIu32,
              CONF_DEFAULT_CROSS_AZ_SURCHARGE_US, deflt->cross_az_surcharge_us);
        CHECK(deflt->latency_band_factor == CONF_DEFAULT_LATENCY_BAND_FACTOR,
              "omitted latency_band_factor must default to %u, got %"PRIu32,
              CONF_DEFAULT_LATENCY_BAND_FACTOR, deflt->latency_band_factor);
    }
    if (bz != NULL) {
        CHECK(bz->latency_band_factor == 0,
              "latency_band_factor:0 must pass through (keep-all), got %"PRIu32,
              bz->latency_band_factor);
    }

    teardown(ctx, cf);
    nc_free(ctx);
}

/*
 * (4a): a pool that sets zone_weight emits a deprecation warning during
 * validation. We capture stderr (where log_init(NULL) writes) to a temp file,
 * parse, restore stderr, then grep the captured text for "deprecat".
 */
static void
test_zone_weight_deprecation_warns(void)
{
    static const char *CONF =
        "pools:\n"
        "    legacy:\n"
        "        listen: 127.0.0.1:11204\n"
        "        redis: true\n"
        "        dynamic_endpoint: false\n"
        "        zone_weight: 80\n"
        "        servers:\n"
        "            - 127.0.0.1:6404:1\n";

    const char *dir = getenv("TMPDIR");
    if (dir == NULL || dir[0] == '\0') dir = "/tmp";
    char cappath[256];
    snprintf(cappath, sizeof(cappath), "%s/twem-warn-XXXXXX", dir);
    int capfd = mkstemp(cappath);
    ASSERT(capfd >= 0);

    /* Redirect stderr (fd 2) -> the capture file across the parse. */
    fflush(stderr);
    int saved = dup(2);
    ASSERT(saved >= 0);
    dup2(capfd, 2);

    struct context *ctx = mk_ctx();
    struct conf *cf = parse_and_transform(CONF, ctx);

    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    close(capfd);

    CHECK(cf != NULL, "config with zone_weight must still parse (back-compat)");

    /* Read the captured warnings back. */
    char buf[8192];
    ssize_t n = 0;
    int rfd = open(cappath, O_RDONLY);
    if (rfd >= 0) {
        n = read(rfd, buf, sizeof(buf) - 1);
        close(rfd);
    }
    if (n < 0) n = 0;
    buf[n] = '\0';
    unlink(cappath);

    /*
     * The deprecation warning is emitted by the real conf_validate_pool. Against
     * the PRE-Task-5 tree it does not exist yet, so this is red there; under the
     * -DTEST_PREFIX_NO_PARSE mirror (which runs the real, patched validator) it
     * fires, so this passes -- the mirror's staged red is the transform-clobber
     * in test (1). See the file header "Red->green".
     */
    bool warned = (strstr(buf, "deprecat") != NULL);
    CHECK(warned,
          "setting zone_weight must emit a deprecation warning during "
          "validation (captured stderr did not contain \"deprecat\")");

    if (cf != NULL) {
        teardown(ctx, cf);
    }
    nc_free(ctx);
}

/*
 * (4b): a config that NEVER sets zone_weight must NOT emit the deprecation
 * warning. Guards against the warning firing on the default-applied path.
 */
static void
test_no_zone_weight_no_deprecation(void)
{
    static const char *CONF =
        "pools:\n"
        "    clean:\n"
        "        listen: 127.0.0.1:11205\n"
        "        redis: true\n"
        "        dynamic_endpoint: false\n"
        "        servers:\n"
        "            - 127.0.0.1:6405:1\n";

    const char *dir = getenv("TMPDIR");
    if (dir == NULL || dir[0] == '\0') dir = "/tmp";
    char cappath[256];
    snprintf(cappath, sizeof(cappath), "%s/twem-nowarn-XXXXXX", dir);
    int capfd = mkstemp(cappath);
    ASSERT(capfd >= 0);

    fflush(stderr);
    int saved = dup(2);
    ASSERT(saved >= 0);
    dup2(capfd, 2);

    struct context *ctx = mk_ctx();
    struct conf *cf = parse_and_transform(CONF, ctx);

    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    close(capfd);

    CHECK(cf != NULL, "clean config must parse");

    char buf[8192];
    ssize_t n = 0;
    int rfd = open(cappath, O_RDONLY);
    if (rfd >= 0) {
        n = read(rfd, buf, sizeof(buf) - 1);
        close(rfd);
    }
    if (n < 0) n = 0;
    buf[n] = '\0';
    unlink(cappath);

    CHECK(strstr(buf, "deprecat") == NULL,
          "a config without zone_weight must NOT emit a deprecation warning");

    if (cf != NULL) {
        teardown(ctx, cf);
    }
    nc_free(ctx);
}

int
main(void)
{
    /* log_warn writes to stderr; without log_init the macro guard reads an
     * uninitialised level. Initialise to WARN so warnings are loggable. */
    if (log_init(LOG_WARN, NULL) != 0) {
        fprintf(stderr, "log_init failed\n");
        return 2;
    }

    test_knobs_parse_and_default();
    test_zone_weight_deprecation_warns();
    test_no_zone_weight_no_deprecation();

    log_deinit();

    if (failures == 0) {
        printf("OK: all conf latency-knob + zone_weight-deprecation tests passed\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d assertion(s)\n", failures);
    return 1;
}
