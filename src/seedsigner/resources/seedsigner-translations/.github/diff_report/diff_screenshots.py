"""
Utility to compare screenshots before and after a change and generate a report of the
differences.

Expected usage in a GitHub Actions workflow; compare `dev` with the `$INCOMING_CHANGES_REF` in the
associated PR or merge that triggered the CI run:
python src/seedsigner/resources/seedsigner-translations/.github/diff_report/diff_screenshots.py ./artifacts/dev ./artifacts/incoming ./artifacts/diff $INCOMING_CHANGES_REF
"""
import argparse
import glob
import hashlib
import os
import pathlib
import shutil


parser = argparse.ArgumentParser(prog=__name__)

parser.add_argument("before_dir", type=str, help="Directory containing screenshots before the incoming changes")
parser.add_argument("after_dir", type=str, help="Directory containing screenshots after the incoming changes")
parser.add_argument("output_dir", type=str, help="Directory to save the screenshots diff report")
parser.add_argument("incoming_changes_ref", type=str, help="Branch name or commit hash that contains the incoming changes")

args = parser.parse_args()

# `before_dir` includes the branch name we'll be merging into
baseline_branch = args.before_dir.split(os.path.sep)[-1]
incoming_changes_ref = args.incoming_changes_ref

def list_files_recursively(path: str) -> list[str]:
    """ Return a list of paths to all png files in the directory tree """
    return glob.glob(path + "/**/*.png", recursive=True)


def compute_file_hash(file_path: str) -> str:
    """ Return the file hash using sha256 """
    hash_func = hashlib.new('sha256')
    
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):  # Read the file in chunks of 8192 bytes
            hash_func.update(chunk)
    
    return hash_func.hexdigest()


def get_pathname_fragment(path:str) -> str:
    """ Extract the last 3 parts of the path:
            en/tools_views/ToolsCalcFinalWordDoneView.png

        These paths will be the same in the "before" and "after" directories.
    """
    parts = path.split(os.path.sep)
    if len(parts) < 3:
        raise ValueError(f"Path should have at least 3 parts: {path}")
    return os.path.sep.join(parts[-3:])


def get_locale_and_screenshot_name(path: str) -> tuple[str, str]:
    """ Parse the path to extract the locale and the screenshot name.

        Assumes we're working with a path like:
            en/tools_views/ToolsCalcFinalWordDoneView.png
    """
    parts = path.split(os.path.sep)
    if len(parts) != 3:
        raise ValueError(f"Path should have 3 parts: {path}")
    return parts[0], parts[-1].split(".")[0]


# Recursively list and hash all png files in the "before" directory
before_screenshots = {}
paths_before = []
for file in list_files_recursively(args.before_dir):
    screenshot_path = get_pathname_fragment(file)
    before_screenshots[screenshot_path] = compute_file_hash(file)
    paths_before.append(screenshot_path)

# Do the same for the "after" directory, but do the diff while we're here
only_in_after = []
diffs: list[str] = []
paths_after = []
for file in list_files_recursively(args.after_dir):
    screenshot_path = get_pathname_fragment(file)
    if screenshot_path not in before_screenshots:
        only_in_after.append(screenshot_path)

    elif before_screenshots[screenshot_path] != compute_file_hash(file):
        diffs.append(screenshot_path)
    
    paths_after.append(screenshot_path)

only_in_before = set(paths_before) - set(paths_after)

html_content = "<h1>Screenshots diff report</h1>"
html_content += f"""<p>Comparing {baseline_branch} to {incoming_changes_ref}</p>"""
output_dir_before = os.path.join(args.output_dir, "before")
output_dir_after = os.path.join(args.output_dir, "after")
os.makedirs(output_dir_before, exist_ok=True)
os.makedirs(output_dir_after, exist_ok=True)

for screenshot_path in only_in_before:
    locale, screenshot_name = get_locale_and_screenshot_name(screenshot_path)
    print(f"Screenshot only in before: {locale}: {screenshot_name}")
    os.makedirs(os.path.join(output_dir_before, os.path.dirname(screenshot_path)), exist_ok=True)
    shutil.copy(os.path.join(args.before_dir, screenshot_path), os.path.join(output_dir_before, screenshot_path))
    html_content += f"<p>{locale}: REMOVED {screenshot_name}</br><img src='{os.path.join('before', screenshot_path)}'></p></br></br>"

for screenshot_path in only_in_after:
    locale, screenshot_name = get_locale_and_screenshot_name(screenshot_path)
    print(f"Screenshot only in after: {locale}: {screenshot_name}")
    os.makedirs(os.path.join(output_dir_after, os.path.dirname(screenshot_path)), exist_ok=True)
    shutil.copy(os.path.join(args.after_dir, screenshot_path), os.path.join(output_dir_after, screenshot_path))
    html_content += f"<p>{locale}: ADDED {screenshot_name}</br><img src='{os.path.join('after', screenshot_path)}'></p></br></br>"

for screenshot_path in diffs:
    locale, screenshot_name = get_locale_and_screenshot_name(screenshot_path)
    print(f"Screenshot different: {locale}: {screenshot_name}")
    # Copy both screenshots to the output dir
    os.makedirs(os.path.join(output_dir_before, os.path.dirname(screenshot_path)), exist_ok=True)
    os.makedirs(os.path.join(output_dir_after, os.path.dirname(screenshot_path)), exist_ok=True)
    shutil.copy(os.path.join(args.before_dir, screenshot_path), os.path.join(output_dir_before, screenshot_path))
    shutil.copy(os.path.join(args.after_dir, screenshot_path), os.path.join(output_dir_after, screenshot_path))
    html_content += f"<p>{locale}: {screenshot_name}</br><img src='{os.path.join('before', screenshot_path)}'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<img src='{os.path.join('after', screenshot_path)}'></p></br></br>"

if not only_in_after and not only_in_before and not diffs:
    print("No differences found")
    html_content += "<h1>No differences found</h1>"

script_dir = pathlib.Path(__file__).parent.resolve()
html_output = ""
with open(os.path.join(script_dir, "index.html"), "r") as f:
    html_output = f.read().replace("{{ content }}", html_content)

with open(os.path.join(args.output_dir, "index.html"), "w") as f:
    f.write(html_output)

# Also copy the css file; source: https://github.com/picocss/pico
shutil.copy(os.path.join(script_dir, "pico.min.css"), os.path.join(args.output_dir, "pico.min.css"))
