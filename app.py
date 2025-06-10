import os
import json
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
UPLOAD_FOLDER = "processed"
LOGS_FILE = "logs.json"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)



def get_json_files():
    """Fetch all JSON files from the upload directory."""
    return sorted([f for f in os.listdir(UPLOAD_FOLDER) if f.endswith(".json")])

def load_json_content(filename):
    """Load JSON content from a selected file."""
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format!"}
    return {"error": "File not found!"}

@app.route("/", methods=["GET", "POST"])
def index():
    files = get_json_files()
    phishing_result = bert_result = creen_result = threat_result = vt_api_key = None
    selected_file = files[-1] if files else None  # Auto-select the latest file

    if request.method == "POST":
        if "selected_file" in request.form:  
            selected_file = request.form.get("selected_file")
        
        if "file" in request.files:  # Handle file upload
            file = request.files["file"]
            if file.filename != "" and file.filename.endswith(".json"):
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
                file.save(file_path)
                selected_file = file.filename  # Auto-select the uploaded file

                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        uploaded_data = json.load(f)
                        if isinstance(uploaded_data, list) and uploaded_data:
                            uploaded_data = uploaded_data[0]  # Extract first dictionary if list
                        #append_to_logs(uploaded_data)
                except json.JSONDecodeError:
                    pass  # Handle invalid JSON cases gracefully

    # Load the latest or selected file's content
    uploaded_data = load_json_content(selected_file) if selected_file else {}
    phishing_result = uploaded_data.get("phishing_result")
    bert_result = uploaded_data.get("bert_result")
    creen_result = uploaded_data.get("creen_result")
    threat_result = uploaded_data.get("threat_result")
    vt_api_key = uploaded_data.get("vt_api_key_provided")

    return render_template(
        "index.html",
        files=files,
        selected_file=selected_file,
        phishing_result=phishing_result,
        bert_result=bert_result,
        creen_result=creen_result,
        threat_result=threat_result,
        vt_api_key=vt_api_key,
    )

@app.route("/get_files")
def get_files():
    """Return the list of JSON files (for dropdown update)."""
    return jsonify(get_json_files())

@app.route("/get_latest_file")
def get_latest_file():
    """Return the latest JSON file and its content."""
    files = get_json_files()
    latest_file = files[-1] if files else None
    return jsonify({
        "latest_file": latest_file,
        "data": load_json_content(latest_file) if latest_file else {}
    })


if __name__ == "__main__":
    app.run(debug=True, port=8200)
