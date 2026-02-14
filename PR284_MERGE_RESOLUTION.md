# PR #284 Merge Conflict Resolution Guide

## Problem

PR #284 (https://github.com/3rdIteration/seedsigner/pull/284) is trying to merge upstream SeedSigner dev branch into the luckfox-pico-stock branch but cannot be merged due to conflicts in `src/seedsigner/hardware/camera.py`.

## Why the Conflict Exists

The luckfox-pico-stock branch has a customized camera implementation:
- Uses v4l2-ctl via a modified PiVideoStream (doesn't use PiCamera library)
- PiVideoStream reads from hardware config in Settings instead of taking parameters
- Simplified API without single-frame capture mode

The upstream dev branch added:
1. `CameraConnectionError` exception class for better error handling
2. Try/except blocks for PiCameraError
3. Parameters to `start_video_stream_mode(resolution, framerate, format)`
4. New methods: `start_single_frame_mode()`, `stop_single_frame_mode()`
5. Different `read_video_stream()` implementation using numpy arrays

## Solution

The resolved `camera.py` file is provided as `camera_resolved.py` in this directory. It merges both implementations:

### Key changes in the resolution:
1. **Added `CameraConnectionError`** - For API compatibility with upstream
2. **Updated `start_video_stream_mode()` signature** - Accepts parameters but ignores them (luckfox uses Settings/hardware config)
3. **Kept luckfox's `read_video_stream()`** - Uses PIL Image.frombytes instead of numpy
4. **Added `_picamera` attribute and single-frame methods** - With ImportError handling since picamera may not be available on luckfox
5. **Updated `capture_frame()`** - Works with both video stream mode (luckfox) and picamera mode (upstream)

## How to Apply This Resolution

### Option 1: Using git merge (Recommended)

```bash
# 1. Checkout the base branch
git checkout luckfox-pico-stock

# 2. Start the merge with upstream
git fetch https://github.com/SeedSigner/seedsigner.git dev
git merge --no-commit --no-ff --allow-unrelated-histories FETCH_HEAD

# 3. The merge will fail with conflicts. Replace the conflicted file:
cp camera_resolved.py src/seedsigner/hardware/camera.py

# 4. Mark as resolved and commit
git add src/seedsigner/hardware/camera.py
git commit -m "Merge upstream dev into luckfox-pico-stock

Resolved conflict in camera.py by:
- Adding CameraConnectionError for API compatibility
- Keeping luckfox v4l2-ctl implementation
- Adding upstream single-frame mode with fallback handling
- Unifying capture_frame for both modes"

# 5. Push to make PR #284 mergeable
git push origin luckfox-pico-stock
```

### Option 2: Manual file replacement

If you just want to update camera.py without a full merge:

```bash
git checkout luckfox-pico-stock
cp camera_resolved.py src/seedsigner/hardware/camera.py
git add src/seedsigner/hardware/camera.py
git commit -m "Update camera.py for upstream compatibility"
git push origin luckfox-pico-stock
```

## Testing

After applying the resolution, test that:
1. The camera still works on luckfox hardware
2. The v4l2-ctl based video streaming functions correctly
3. Frame capture works as expected
4. No import errors occur

## Additional Notes

- The `camera_resolved.py` file includes comments explaining platform-specific behavior
- The single-frame mode methods will raise `CameraConnectionError` if picamera is not available
- This resolution maintains backward compatibility with luckfox while adding upstream API compatibility
