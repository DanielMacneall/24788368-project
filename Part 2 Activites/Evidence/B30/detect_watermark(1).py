"""
B30 - Stage 3: Detect and extract the DCT watermark from an image
How it works:
  1. Load the image and extract the Y channel
  2. Divide into 8x8 blocks and apply DCT
  3. Read the sign of the mid-frequency coefficient in each block
  4. Reconstruct bits -> characters -> message
  5. Compare to original watermark and report confidence score
"""

import numpy as np
from PIL import Image
from scipy.fftpack import dct
import sys

WATERMARK_TEXT = "CITS2006_B30"
BLOCK_SIZE     = 8

def text_to_bits(text):
    bits = []
    for char in text:
        ascii_val = ord(char)
        for i in range(7, -1, -1):
            bits.append((ascii_val >> i) & 1)
    return bits

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i+8]
        ascii_val = sum(b << (7 - j) for j, b in enumerate(byte))
        if 32 <= ascii_val <= 126:   # printable ASCII only
            chars.append(chr(ascii_val))
        else:
            chars.append('?')
    return ''.join(chars)

def apply_dct_2d(block):
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

def detect_watermark(image_path):
    img = Image.open(image_path).convert('YCbCr')
    y_channel = np.array(img)[:, :, 0].astype(np.float64)
    height, width = y_channel.shape

    original_bits = text_to_bits(WATERMARK_TEXT)
    num_bits_needed = len(original_bits)

    extracted_bits = []

    for row in range(0, height - BLOCK_SIZE + 1, BLOCK_SIZE):
        for col in range(0, width - BLOCK_SIZE + 1, BLOCK_SIZE):
            if len(extracted_bits) >= num_bits_needed:
                break
            block = y_channel[row:row+BLOCK_SIZE, col:col+BLOCK_SIZE]
            dct_block = apply_dct_2d(block)
            # Read the sign of position (4,1) — positive = 1, negative = 0
            extracted_bits.append(1 if dct_block[4][1] > 0 else 0)

    # Calculate how many bits match
    matches = sum(e == o for e, o in zip(extracted_bits, original_bits))
    confidence = (matches / num_bits_needed) * 100
    extracted_text = bits_to_text(extracted_bits)

    print(f"\n{'='*50}")
    print(f"WATERMARK DETECTION REPORT")
    print(f"{'='*50}")
    print(f"Image analysed:    {image_path}")
    print(f"Expected message:  '{WATERMARK_TEXT}'")
    print(f"Extracted message: '{extracted_text}'")
    print(f"Bits matched:      {matches}/{num_bits_needed}")
    print(f"Confidence score:  {confidence:.1f}%")
    print(f"{'='*50}")

    if confidence >= 90:
        print("RESULT: Watermark SURVIVED ✓")
    elif confidence >= 70:
        print("RESULT: Watermark PARTIALLY survived (~)")
    else:
        print("RESULT: Watermark DESTROYED ✗")
    print(f"{'='*50}\n")

    return confidence

if __name__ == "__main__":
    image_path = sys.argv[1] if len(sys.argv) > 1 else "watermarked.png"
    detect_watermark(image_path)
