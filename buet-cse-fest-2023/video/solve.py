import cv2
import os

def extract_frames(video_path, output_dir):
    # Open the video file
    video = cv2.VideoCapture(video_path)

    # Check if the video file was successfully opened
    if not video.isOpened():
        print("Error opening video file")
        return

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    frame_count = 0

    # Read frames until the video is complete
    while video.isOpened():
        # Read the current frame
        ret, frame = video.read()

        # Check if a frame was successfully read
        if not ret:
            break

        # Save the frame as a PNG image
        output_path = os.path.join(output_dir, f"frame_{frame_count}.png")
        cv2.imwrite(output_path, frame)

        frame_count += 1

    # Release the video file
    video.release()

    print(f"Frames extracted: {frame_count}")

# Specify the path to your video file
video_path = "video.mp4"

# Specify the output directory where the frames will be saved
output_dir = "./frames"

# Call the function to extract frames
extract_frames(video_path, output_dir)