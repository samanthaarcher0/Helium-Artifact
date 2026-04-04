// combined_harness.cpp
//
// Combines the box blur convolution harness (BGRAConvolve2D / SkConvolver)
// with the bitwise pixel transform harness (shifts, masks, XOR) into one
// file.  Both operate on the same BGRA src arrays defined per run_NxN().
//
// Build:
//   g++ -std=c++17 -O0 -g \
//       -I../firefox/gfx/2d \
//       -I../firefox/mfbt \
//       -I../firefox/mfbt/.. \
//       -msse2 -DNO_DYNAMIC_CAST -fno-exceptions \
//       -o workloads/combined \
//       workloads/combined_harness.cpp \
//       ../firefox/gfx/2d/SkConvolver.cpp \
//       workloads/stubs.cpp

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "SkConvolver.h"    // BGRAConvolve2D, SkConvolutionFilter1D
#include "Types.h"          // mozilla::gfx::SurfaceFormat

#undef MOZILLA_MAY_SUPPORT_SSE2

using namespace skia;
using mozilla::gfx::SurfaceFormat;
using Fixed = SkConvolutionFilter1D::ConvolutionFixed;

static const int BPP = 4;   // BGRA — 4 bytes per pixel

// ---------------------------------------------------------------------------
// Shared utility
// ---------------------------------------------------------------------------

static Fixed f2fx(float f) {
    return static_cast<Fixed>(f * 16384.0f + 0.5f);
}

// dump for raw pointer (used by convolution path, which writes into a flat
// dst buffer the same way the original box_blur_harness did)
static void dump(const char* label, const uint8_t* buf, int W, int H) {
    printf("%s\n", label);
    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            const uint8_t* p = buf + (y * W + x) * BPP;
            printf("(%3u,%3u,%3u,%3u) ", p[0], p[1], p[2], p[3]);
        }
        printf("\n");
    }
    printf("\n");
}

// ---------------------------------------------------------------------------
// Minimal surface descriptor — mirrors DataSourceSurface::MappedSurface.
// Used by the bitwise transform path.  mStride kept separate from W*BPP so
// the shape matches the real Firefox type if you ever slot it in.
// ---------------------------------------------------------------------------
struct MappedSurface {
    uint8_t*        mData;
    int32_t         mStride;
    int             mWidth;
    int             mHeight;
    SurfaceFormat   mFormat;
};

static MappedSurface AllocSurface(int W, int H, SurfaceFormat fmt) {
    MappedSurface s;
    s.mWidth  = W;
    s.mHeight = H;
    s.mFormat = fmt;
    s.mStride = W * BPP;
    s.mData   = (uint8_t*)calloc(H * s.mStride, 1);
    return s;
}

static void FreeSurface(MappedSurface& s) {
    free(s.mData);
    s.mData = nullptr;
}

static MappedSurface MakeSurface(int W, int H, const uint8_t* srcPixels) {
    MappedSurface s = AllocSurface(W, H, SurfaceFormat::B8G8R8A8);
    for (int y = 0; y < H; y++)
        memcpy(s.mData + y * s.mStride, srcPixels + y * W * BPP, W * BPP);
    return s;
}

// dump overload for MappedSurface (used by bitwise transform path)
static void dump(const char* label, const MappedSurface& s) {
    dump(label, s.mData, s.mWidth, s.mHeight);
}

// ---------------------------------------------------------------------------
// Box blur helpers
// ---------------------------------------------------------------------------

// Populate a 1D convolution filter with clamped [1/3,1/3,1/3] box blur
// coefficients for an N-pixel row/column.
static void add_box_blur_filters(SkConvolutionFilter1D& f, int N) {
    const float t = 1.0f / 3.0f;
    if (N == 2) {
        { Fixed w[2] = { f2fx(2.0f/3.0f), f2fx(1.0f/3.0f) }; f.AddFilter(0, w, 2); }
        { Fixed w[2] = { f2fx(1.0f/3.0f), f2fx(2.0f/3.0f) }; f.AddFilter(0, w, 2); }
    } else if (N == 3) {
        { Fixed w[2] = { f2fx(0.5f),  f2fx(0.5f)         }; f.AddFilter(0, w, 2); }
        { Fixed w[3] = { f2fx(t),     f2fx(t),   f2fx(t) }; f.AddFilter(0, w, 3); }
        { Fixed w[2] = { f2fx(0.5f),  f2fx(0.5f)         }; f.AddFilter(1, w, 2); }
    } else if (N == 4) {
        { Fixed w[2] = { f2fx(2.0f/3.0f), f2fx(1.0f/3.0f) }; f.AddFilter(0, w, 2); }
        { Fixed w[3] = { f2fx(t), f2fx(t), f2fx(t) };         f.AddFilter(0, w, 3); }
        { Fixed w[3] = { f2fx(t), f2fx(t), f2fx(t) };         f.AddFilter(1, w, 3); }
        { Fixed w[2] = { f2fx(1.0f/3.0f), f2fx(2.0f/3.0f) }; f.AddFilter(2, w, 2); }
    }
}

// ---------------------------------------------------------------------------
// Bitwise transforms
// ---------------------------------------------------------------------------

// Posterize: keep only top N bits of each channel.  mask=0xF0 -> 4 bits.
static void transform_posterize(MappedSurface& s, uint8_t mask) {
    for (int y = 0; y < s.mHeight; y++) {
        uint8_t* row = s.mData + y * s.mStride;
        for (int x = 0; x < s.mWidth; x++) {
            uint8_t* p = row + x * BPP;
            p[0] &= mask;   // B
            p[1] &= mask;   // G
            p[2] &= mask;   // R
            // p[3] alpha left intact
        }
    }
}

// XOR channel swap B <-> R: classic 3-step, no temp variable.
static void transform_swap_br_xor(MappedSurface& s) {
    for (int y = 0; y < s.mHeight; y++) {
        uint8_t* row = s.mData + y * s.mStride;
        for (int x = 0; x < s.mWidth; x++) {
            uint8_t* p = row + x * BPP;
            p[0] ^= p[2];
            p[2] ^= p[0];
            p[0] ^= p[2];
        }
    }
}

// Pack to uint32 via shifts+OR, zero green channel, unpack back.
// Mirrors Color::ToABGR() / Color::FromABGR() in gfx/2d/Types.h.
static void transform_kill_green_packed(MappedSurface& s) {
    for (int y = 0; y < s.mHeight; y++) {
        uint8_t* row = s.mData + y * s.mStride;
        for (int x = 0; x < s.mWidth; x++) {
            uint8_t* p = row + x * BPP;

            uint32_t px = (uint32_t)p[0]        |   // B -> bits  [7:0]
                          (uint32_t)p[1] <<  8  |   // G -> bits [15:8]
                          (uint32_t)p[2] << 16  |   // R -> bits [23:16]
                          (uint32_t)p[3] << 24;     // A -> bits [31:24]

            px &= ~(0xFFu << 8);    // clear G channel bits [15:8]

            p[0] = (px >>  0) & 0xFF;
            p[1] = (px >>  8) & 0xFF;   // will be 0
            p[2] = (px >> 16) & 0xFF;
            p[3] = (px >> 24) & 0xFF;
        }
    }
}

// Reverse bit order in the blue channel byte via shift-accumulate.
static uint8_t reverse_bits(uint8_t v) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        r = (uint8_t)((r << 1) | (v & 1));
        v >>= 1;
    }
    return r;
}

static void transform_reverse_bits_blue(MappedSurface& s) {
    for (int y = 0; y < s.mHeight; y++) {
        uint8_t* row = s.mData + y * s.mStride;
        for (int x = 0; x < s.mWidth; x++) {
            uint8_t* p = row + x * BPP;
            p[0] = reverse_bits(p[0]);  // B channel only
        }
    }
}

// (R >> 7) & 1 isolates the MSB; produces a binary B&W image.
static void transform_threshold_red_msb(MappedSurface& s) {
    for (int y = 0; y < s.mHeight; y++) {
        uint8_t* row = s.mData + y * s.mStride;
        for (int x = 0; x < s.mWidth; x++) {
            uint8_t* p = row + x * BPP;
            uint8_t val = (uint8_t)(((p[2] >> 7) & 1) * 255); // R is byte[2]
            p[0] = p[1] = p[2] = val;
            p[3] = 255;
        }
    }
}

// Nibble interleave: dst[c] = (cur[c] & 0xF0) | ((next[c] >> 4) & 0x0F)
static void transform_nibble_interleave(MappedSurface& s) {
    MappedSurface tmp = AllocSurface(s.mWidth, s.mHeight, s.mFormat);
    for (int y = 0; y < s.mHeight; y++)
        memcpy(tmp.mData + y * tmp.mStride, s.mData + y * s.mStride,
               s.mWidth * BPP);

    int pixels = s.mWidth * s.mHeight;
    for (int y = 0; y < s.mHeight; y++) {
        uint8_t*       dstRow = s.mData   + y * s.mStride;
        const uint8_t* srcRow = tmp.mData + y * tmp.mStride;
        for (int x = 0; x < s.mWidth; x++) {
            uint8_t*       dst  = dstRow + x * BPP;
            const uint8_t* cur  = srcRow + x * BPP;
            int nextIdx         = (y * s.mWidth + x + 1) % pixels;
            const uint8_t* next = tmp.mData
                                + (nextIdx / s.mWidth) * tmp.mStride
                                + (nextIdx % s.mWidth) * BPP;
            for (int c = 0; c < 3; c++)
                dst[c] = (cur[c] & 0xF0) | ((next[c] >> 4) & 0x0F);
            dst[3] = cur[3];
        }
    }
    FreeSurface(tmp);
}

// Allocate a fresh surface from src, run transform fn, dump, free.
#define RUN_BITWISE(label, fn)                          \
{                                                       \
    MappedSurface s = MakeSurface(W, H, src);           \
    fn;                                                 \
    FreeSurface(s);                                     \
}
    // dump(label, s);                                     \
}

// ---------------------------------------------------------------------------
// 2x2
// ---------------------------------------------------------------------------
static void run_2x2(void) {
    static const int W = 2, H = 2;
    static const int STRIDE = W * BPP;

    uint8_t src[W * H * BPP] = {
        // row 0
         30,  20,  10, 255,   60,  50,  40, 255,
        // row 1
        120, 110, 100, 255,  150, 140, 130, 255,
    };

    // dump("SRC 2x2 (BGRA)", src, W, H);

    // --- Convolution: clamped [1/3,1/3,1/3] box blur ---
    {
        uint8_t dst[W * H * BPP];
        memset(dst, 0, sizeof(dst));

        SkConvolutionFilter1D fx, fy;
        add_box_blur_filters(fx, W);
        add_box_blur_filters(fy, H);

        bool ok = BGRAConvolve2D(src, STRIDE, SurfaceFormat::B8G8R8X8,
                                 fx, fy, STRIDE, dst);
        if (!ok) fprintf(stderr, "BGRAConvolve2D 2x2 failed\n");
    //     else     dump("Box blur 2x2 (uniform [1,1,1]/3)", dst, W, H);
    }

    // --- Bitwise transforms ---
    RUN_BITWISE("Posterize mask=0xF0 (top 4 bits per channel)",
        transform_posterize(s, 0xF0));
    RUN_BITWISE("XOR channel swap (B <-> R)",
        transform_swap_br_xor(s));
    RUN_BITWISE("Pack/unpack: zero green channel via uint32 bit mask",
        transform_kill_green_packed(s));
    RUN_BITWISE("Bit reversal of blue channel",
        transform_reverse_bits_blue(s));
    RUN_BITWISE("Threshold: R MSB (>> 7) -> B&W mask",
        transform_threshold_red_msb(s));
    RUN_BITWISE("Nibble interleave: top-4 of cur | bottom-4 of next",
        transform_nibble_interleave(s));
}

// ---------------------------------------------------------------------------
// 3x3
// ---------------------------------------------------------------------------
static void run_3x3(void) {
    static const int W = 3, H = 3;
    static const int STRIDE = W * BPP;

    uint8_t src[W * H * BPP] = {
        // row 0
         30,  20,  10, 255,   60,  50,  40, 255,   90,  80,  70, 255,
        // row 1
        120, 110, 100, 255,  150, 140, 130, 255,  180, 170, 160, 255,
        // row 2
        210, 200, 190, 255,  240, 230, 220, 255,   35,  15, 250, 255,
    };

    // dump("SRC 3x3 (BGRA)", src, W, H);

    // --- Convolution: clamped [1/3,1/3,1/3] box blur ---
    {
        uint8_t dst[W * H * BPP];
        memset(dst, 0, sizeof(dst));

        SkConvolutionFilter1D fx, fy;
        add_box_blur_filters(fx, W);
        add_box_blur_filters(fy, H);

        bool ok = BGRAConvolve2D(src, STRIDE, SurfaceFormat::B8G8R8X8,
                                 fx, fy, STRIDE, dst);
        if (!ok) fprintf(stderr, "BGRAConvolve2D 3x3 failed\n");
        // else     dump("Box blur 3x3 (uniform [1,1,1]/3)", dst, W, H);
    }

    // --- Bitwise transforms ---
    RUN_BITWISE("Posterize mask=0xF0 (top 4 bits per channel)",
        transform_posterize(s, 0xF0));
    RUN_BITWISE("XOR channel swap (B <-> R)",
        transform_swap_br_xor(s));
    RUN_BITWISE("Pack/unpack: zero green channel via uint32 bit mask",
        transform_kill_green_packed(s));
    RUN_BITWISE("Bit reversal of blue channel",
        transform_reverse_bits_blue(s));
    RUN_BITWISE("Threshold: R MSB (>> 7) -> B&W mask",
        transform_threshold_red_msb(s));
    RUN_BITWISE("Nibble interleave: top-4 of cur | bottom-4 of next",
        transform_nibble_interleave(s));
}

// ---------------------------------------------------------------------------
// 4x4
// ---------------------------------------------------------------------------
static void run_4x4(void) {
    static const int W = 4, H = 4;
    static const int STRIDE = W * BPP;

    uint8_t src[W * H * BPP] = {
        // row 0
         30,  20,  10, 255,   60,  50,  40, 255,   90,  80,  70, 255,  120, 110, 100, 255,
        // row 1
        150, 140, 130, 255,  180, 170, 160, 255,  210, 200, 190, 255,  240, 230, 220, 255,
        // row 2
         35,  15, 250, 255,   65,  55,  45, 255,   95,  85,  75, 255,  125, 115, 105, 255,
        // row 3
        155, 145, 135, 255,  185, 175, 165, 255,  215, 205, 195, 255,  245, 235, 225, 255,
    };

    // dump("SRC 4x4 (BGRA)", src, W, H);

    // --- Convolution: clamped [1/3,1/3,1/3] box blur ---
    {
        uint8_t dst[W * H * BPP];
        memset(dst, 0, sizeof(dst));

        SkConvolutionFilter1D fx, fy;
        add_box_blur_filters(fx, W);
        add_box_blur_filters(fy, H);

        bool ok = BGRAConvolve2D(src, STRIDE, SurfaceFormat::B8G8R8X8,
                                 fx, fy, STRIDE, dst);
        if (!ok) fprintf(stderr, "BGRAConvolve2D 4x4 failed\n");
        // else     dump("Box blur 4x4 (uniform [1,1,1]/3)", dst, W, H);
    }

    // --- Bitwise transforms ---
    RUN_BITWISE("Posterize mask=0xF0 (top 4 bits per channel)",
        transform_posterize(s, 0xF0));
    RUN_BITWISE("XOR channel swap (B <-> R)",
        transform_swap_br_xor(s));
    RUN_BITWISE("Pack/unpack: zero green channel via uint32 bit mask",
        transform_kill_green_packed(s));
    RUN_BITWISE("Bit reversal of blue channel",
        transform_reverse_bits_blue(s));
    RUN_BITWISE("Threshold: R MSB (>> 7) -> B&W mask",
        transform_threshold_red_msb(s));
    RUN_BITWISE("Nibble interleave: top-4 of cur | bottom-4 of next",
        transform_nibble_interleave(s));
}

#undef RUN_BITWISE

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <size>\n  size: 2, 3, or 4\n", argv[0]);
        return 1;
    }
    int N = atoi(argv[1]);
    if      (N == 2) run_2x2();
    else if (N == 3) run_3x3();
    else if (N == 4) run_4x4();
    else fprintf(stderr, "Unknown size %d, use 2, 3, or 4\n", N);
    return 0;
}
