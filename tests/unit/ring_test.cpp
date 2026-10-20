#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "common/kc_internal.h"
#include "common/kc_ring.h"

namespace {

struct RingFixture {
    std::vector<uint8_t> region;
    kc::DirectRegion direct{};
    kc::RingView ring{};

    explicit RingFixture(uint64_t region_size = 0x10000)
        : region(region_size, 0) {
        kc::direct_region_init(&direct, region.data(), region_size);
        ring.ops = kc::direct_mem_ops();
        ring.ops_ctx = &direct;
        ring.region_size = region_size;
        ring.ring_off = KC_CTRL_SIZE;
        ring.ring_size = KC_RING_SIZE_FOR(region_size);
        ring.head_off = offsetof(kc_ctrl, req_head);
        ring.tail_off = offsetof(kc_ctrl, req_tail);
    }

    uint64_t used() {
        uint64_t value = 0;
        EXPECT_EQ(kc::ring_used(&ring, &value), KC_OK);
        return value;
    }

    void set_head(uint64_t value) {
        kc::put_le64(region.data() + ring.head_off, value);
    }
    void set_tail(uint64_t value) {
        kc::put_le64(region.data() + ring.tail_off, value);
    }
    uint64_t head() { return kc::get_le64(region.data() + ring.head_off); }
};

/* Fills a record of `len` bytes with a recognizable pattern. */
std::vector<uint8_t> make_record(uint64_t seq, uint32_t len, uint8_t seed) {
    std::vector<uint8_t> record(len, 0);
    kc::put_le32(record.data(), len);
    kc::put_le32(record.data() + 4, KC_RECORD_MAGIC);
    kc::put_le64(record.data() + 8, seq);
    for (uint32_t i = KC_RECORD_HEADER_SIZE; i < len; ++i) {
        record[i] = static_cast<uint8_t>(seed + i);
    }
    return record;
}

} /* namespace */

TEST(Ring, PushPopSingle) {
    RingFixture fixture;
    const std::vector<uint8_t> record = make_record(1, 0x100, 7);
    ASSERT_EQ(kc::ring_push(&fixture.ring, record.data(),
                            static_cast<uint32_t>(record.size())),
              KC_OK);
    EXPECT_EQ(fixture.used(), 0x100u);
    std::vector<uint8_t> output(0x100);
    uint32_t length = 0;
    ASSERT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_OK);
    EXPECT_EQ(length, 0x100u);
    EXPECT_EQ(output, record);
    EXPECT_EQ(fixture.used(), 0u);
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_ERR_NOT_FOUND);
}

TEST(Ring, WrapAround) {
    RingFixture fixture(0x4000); /* ring = 0x1000 */
    ASSERT_EQ(fixture.ring.ring_size, 0x1000u);
    /* Advance head close to the end, then push a record that must wrap. */
    const std::vector<uint8_t> first = make_record(1, 0xF80, 1);
    ASSERT_EQ(kc::ring_push(&fixture.ring, first.data(),
                            static_cast<uint32_t>(first.size())),
              KC_OK);
    std::vector<uint8_t> scratch(0xF80);
    uint32_t length = 0;
    ASSERT_EQ(kc::ring_pop(&fixture.ring, scratch.data(),
                           static_cast<uint32_t>(scratch.size()), &length),
              KC_OK);
    ASSERT_EQ(length, 0xF80u);

    const std::vector<uint8_t> crossing = make_record(2, 0x180, 2);
    ASSERT_EQ(kc::ring_push(&fixture.ring, crossing.data(),
                            static_cast<uint32_t>(crossing.size())),
              KC_OK);
    EXPECT_EQ(fixture.head(), 0x100u); /* (0xF80 + 0x180) % 0x1000 */
    std::vector<uint8_t> output(0x180);
    ASSERT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_OK);
    EXPECT_EQ(output, crossing);
}

TEST(Ring, FullAndEmpty) {
    RingFixture fixture(0x4000); /* ring = 0x1000, capacity 0xFF8 */
    std::vector<uint8_t> record = make_record(1, 0x100, 3);
    uint32_t pushed = 0;
    for (;;) {
        const kc_status status = kc::ring_push(
            &fixture.ring, record.data(), static_cast<uint32_t>(record.size()));
        if (status == KC_ERR_BUSY) {
            break;
        }
        ASSERT_EQ(status, KC_OK);
        ++pushed;
        ASSERT_LT(pushed, 100u);
    }
    EXPECT_EQ(pushed, 15u);
    EXPECT_EQ(fixture.used(), 0xF00u);
    std::vector<uint8_t> output(0x100);
    uint32_t length = 0;
    for (uint32_t i = 0; i < pushed; ++i) {
        ASSERT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                               static_cast<uint32_t>(output.size()), &length),
                  KC_OK);
        EXPECT_EQ(length, 0x100u);
    }
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_ERR_NOT_FOUND);
    /* after draining, pushing again works */
    EXPECT_EQ(kc::ring_push(&fixture.ring, record.data(),
                            static_cast<uint32_t>(record.size())),
              KC_OK);
}

TEST(Ring, RejectsCorruptHeadsAndTails) {
    RingFixture fixture(0x4000);
    const std::vector<uint8_t> record = make_record(1, 0x100, 1);
    fixture.set_head(fixture.ring.ring_size); /* out of range */
    EXPECT_EQ(kc::ring_push(&fixture.ring, record.data(),
                            static_cast<uint32_t>(record.size())),
              KC_ERR_IO);
    fixture.set_head(0x103); /* not 8 byte aligned */
    EXPECT_EQ(kc::ring_push(&fixture.ring, record.data(),
                            static_cast<uint32_t>(record.size())),
              KC_ERR_IO);
    fixture.set_head(0x100);
    fixture.set_tail(0xFFFF); /* out of range */
    EXPECT_EQ(kc::ring_push(&fixture.ring, record.data(),
                            static_cast<uint32_t>(record.size())),
              KC_ERR_IO);
}

TEST(Ring, RejectsCorruptRecords) {
    RingFixture fixture(0x4000);
    std::vector<uint8_t> record(0x100, 0);
    kc::put_le32(record.data(), 0x100);
    kc::put_le32(record.data() + 4, KC_RECORD_MAGIC);
    kc::put_le64(record.data() + 8, 1);
    ASSERT_EQ(kc::ring_push(&fixture.ring, record.data(),
                            static_cast<uint32_t>(record.size())),
              KC_OK);
    /* corrupt the magic: consumed? no, pop must report MAGIC and keep tail */
    std::vector<uint8_t> output(0x100);
    uint32_t length = 0;
    kc::put_le32(fixture.region.data() + fixture.ring.ring_off + 4, 0xDEADBEEF);
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_ERR_MAGIC);
    kc::put_le32(fixture.region.data() + fixture.ring.ring_off + 4,
                 KC_RECORD_MAGIC);
    /* length not 8-byte aligned */
    kc::put_le32(fixture.region.data() + fixture.ring.ring_off, 0x101);
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_ERR_IO);
    /* length larger than what is queued */
    kc::put_le32(fixture.region.data() + fixture.ring.ring_off, 0x200);
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_ERR_IO);
    /* length smaller than a record header */
    kc::put_le32(fixture.region.data() + fixture.ring.ring_off, 0x08);
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_ERR_IO);
    /* restore a valid record, then a too-small output buffer */
    kc::put_le32(fixture.region.data() + fixture.ring.ring_off, 0x100);
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(), 0x80, &length),
              KC_ERR_PARAM);
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_OK);
}

TEST(Ring, RejectsInvalidGeometry) {
    RingFixture fixture(0x4000);
    kc::RingView bad = fixture.ring;
    bad.ring_size = 0x100; /* too small */
    EXPECT_EQ(kc::ring_validate(&bad), KC_ERR_PARAM);
    bad = fixture.ring;
    bad.ring_off = 0x10; /* inside the control page */
    EXPECT_EQ(kc::ring_validate(&bad), KC_ERR_PARAM);
    bad = fixture.ring;
    bad.ring_off = fixture.ring.region_size - 0x100; /* overruns the region */
    EXPECT_EQ(kc::ring_validate(&bad), KC_ERR_PARAM);
    bad = fixture.ring;
    bad.ring_size = 0x1001; /* not 8 byte aligned */
    EXPECT_EQ(kc::ring_validate(&bad), KC_ERR_PARAM);
    EXPECT_EQ(kc::ring_validate(nullptr), KC_ERR_PARAM);
}

TEST(Ring, PartialRecordIsCorrupt) {
    RingFixture fixture(0x4000);
    /* only 8 bytes queued: not even a whole record header */
    fixture.set_head(8);
    std::vector<uint8_t> output(0x100);
    uint32_t length = 0;
    EXPECT_EQ(kc::ring_pop(&fixture.ring, output.data(),
                           static_cast<uint32_t>(output.size()), &length),
              KC_ERR_IO);
}
