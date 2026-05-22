"""
B30 - Stage 2: Embed an imperceptible DCT watermark into an image
How it works:
  1. Load image and convert to YCbCr colour space (Y = brightness channel)
  2. Divide the Y channel into 8x8 blocks (same as JPEG)
  3. Apply DCT to each block (converts pixels to frequencies)
  4. Hide watermark bits in the mid-frequency coefficients
  5. Apply inverse DCT and save
"""

import numpy as np
from PIL import Image
from scipy.fftpack import dct, idct
import sys

# ── settings ──────────────────────────────────────────────────────────────────
WATERMARK_TEXT = "CITS2006_B30"   # message to hide
STRENGTH       = 25                   # embedding strength (higher = more robust but slightly visible)
BLOCK_SIZE     = 8                    # standard DCT block size
# ──────────────────────────────────────────────────────────────────────────────

def text_to_bits(text):
    """Convert a string to a list of 0s and 1s"""
    bits = []
    for char in text:
        ascii_val = ord(char)
        for i in range(7, -1, -1):          # 8 bits per character
            bits.append((ascii_val >> i) & 1)
    return bits

def apply_dct_2d(block):
    """Apply 2D DCT to an 8x8 block"""
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

def apply_idct_2d(block):
    """Apply inverse 2D DCT to recover pixel values"""
    return idct(idct(block.T, norm='ortho').T, norm='ortho')

def embed_watermark(image_path, output_path):
    # Load image
    img = Image.open(image_path).convert('RGB')
    img_array = np.array(img, dtype=np.float64)

    # Work on the Y (brightness) channel only — least noticeable to humans
    # Convert RGB to YCbCr
    ycbcr = img.convert('YCbCr')
    y_channel = np.array(ycbcr)[:, :, 0].astype(np.float64)

    height, width = y_channel.shape
    bits = text_to_bits(WATERMARK_TEXT)
    bit_index = 0
    bits_embedded = 0

    print(f"Image size: {width}x{height}")
    print(f"Watermark: '{WATERMARK_TEXT}' ({len(bits)} bits to embed)")

    # Process each 8x8 block
    for row in range(0, height - BLOCK_SIZE + 1, BLOCK_SIZE):
        for col in range(0, width - BLOCK_SIZE + 1, BLOCK_SIZE):
            if bit_index >= len(bits):
                break

            block = y_channel[row:row+BLOCK_SIZE, col:col+BLOCK_SIZE]
            dct_block = apply_dct_2d(block)

            # Embed 1 bit per block in a mid-frequency position
            # Position (4,1) is mid-frequency — invisible but robust
            if bits[bit_index] == 1:
                dct_block[4][1] = abs(dct_block[4][1]) + STRENGTH
            else:
                dct_block[4][1] = -(abs(dct_block[4][1]) + STRENGTH)

            # Inverse DCT to get back pixel values
            y_channel[row:row+BLOCK_SIZE, col:col+BLOCK_SIZE] = apply_idct_2d(dct_block)
            bit_index += 1
            bits_embedded += 1

    print(f"Bits embedded: {bits_embedded}")

    # Clip values to valid pixel range and convert back to uint8
    y_channel = np.clip(y_channel, 0, 255).astype(np.uint8)

    # Rebuild image with watermarked Y channel
    ycbcr_array = np.array(ycbcr)
    ycbcr_array[:, :, 0] = y_channel
    watermarked = Image.fromarray(ycbcr_array, 'YCbCr').convert('RGB')
    watermarked.save(output_path, quality=95)

    print(f"Watermarked image saved to: {output_path}")
    return bits_embedded

if __name__ == "__main__":
    input_image  = sys.argv[1] if len(sys.argv) > 1 else "ai_image.png"
    output_image = sys.argv[2] if len(sys.argv) > 2 else "watermarked.png"
    embed_watermark(input_image, output_image)
