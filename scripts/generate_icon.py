#!/usr/bin/env python3
"""Generate app icon for BrightNexus"""
import subprocess
import os
import json

# Output directory
ICON_DIR = "/Volumes/Code/source/repos/enclave/Enclave/Assets.xcassets/AppIcon.appiconset"

# Sizes needed for macOS app icon
SIZES = [
    (16, 1), (16, 2),
    (32, 1), (32, 2),
    (128, 1), (128, 2),
    (256, 1), (256, 2),
    (512, 1), (512, 2),
]

# Create SVG icon - shield with key
SVG_CONTENT = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1a1a2e"/>
      <stop offset="100%" stop-color="#16213e"/>
    </linearGradient>
    <linearGradient id="shield" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00d4ff"/>
      <stop offset="100%" stop-color="#0099cc"/>
    </linearGradient>
    <linearGradient id="key" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ffd700"/>
      <stop offset="100%" stop-color="#ffaa00"/>
    </linearGradient>
  </defs>
  <rect x="20" y="20" width="472" height="472" rx="90" fill="url(#bg)"/>
  <path d="M256 80 L400 130 L400 280 C400 380 256 440 256 440 C256 440 112 380 112 280 L112 130 Z" 
        fill="none" stroke="url(#shield)" stroke-width="20" stroke-linejoin="round"/>
  <g transform="translate(256, 260) rotate(-45)">
    <circle cx="-60" cy="0" r="50" fill="url(#key)"/>
    <circle cx="-60" cy="0" r="20" fill="url(#bg)"/>
    <rect x="-20" y="-12" width="120" height="24" rx="8" fill="url(#key)"/>
    <rect x="70" y="-12" width="12" height="35" rx="3" fill="url(#key)"/>
    <rect x="90" y="-12" width="12" height="25" rx="3" fill="url(#key)"/>
  </g>
  <circle cx="256" cy="160" r="25" fill="url(#shield)"/>
  <rect x="244" y="155" width="24" height="20" rx="3" fill="url(#bg)"/>
  <path d="M250 155 L250 145 A12 12 0 0 1 262 145 L262 155" fill="none" stroke="url(#bg)" stroke-width="4"/>
</svg>'''

def main():
    # Save SVG
    svg_path = "/tmp/enclave_icon.svg"
    with open(svg_path, "w") as f:
        f.write(SVG_CONTENT)
    print(f"Created SVG at {svg_path}")
    
    os.makedirs(ICON_DIR, exist_ok=True)
    
    images = []
    for size, scale in SIZES:
        actual_size = size * scale
        filename = f"icon_{size}x{size}@{scale}x.png"
        filepath = os.path.join(ICON_DIR, filename)
        
        # Try rsvg-convert (brew install librsvg)
        try:
            result = subprocess.run([
                "rsvg-convert", "-w", str(actual_size), "-h", str(actual_size),
                "-o", filepath, svg_path
            ], capture_output=True, text=True)
            if result.returncode == 0:
                images.append((filename, size, scale))
                print(f"Generated {filename}")
                continue
        except FileNotFoundError:
            pass
        
        print(f"Skipped {filename} - install librsvg: brew install librsvg")
    
    # Update Contents.json
    contents = {"images": [], "info": {"author": "xcode", "version": 1}}
    for filename, size, scale in images:
        contents["images"].append({
            "filename": filename,
            "idiom": "mac",
            "scale": f"{scale}x",
            "size": f"{size}x{size}"
        })
    
    # Add entries for missing sizes
    existing = {(s, sc) for _, s, sc in images}
    for size, scale in SIZES:
        if (size, scale) not in existing:
            contents["images"].append({
                "idiom": "mac",
                "scale": f"{scale}x",
                "size": f"{size}x{size}"
            })
    
    contents_path = os.path.join(ICON_DIR, "Contents.json")
    with open(contents_path, "w") as f:
        json.dump(contents, f, indent=2)
    print(f"Updated {contents_path}")

if __name__ == "__main__":
    main()
