import os
import pandas as pd
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
import numpy as np

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def partial_mask_data(data):
    if pd.isnull(data):
        return '****'
    elif isinstance(data, str):
        return data[0] + '*' * (len(data) - 2) + data[-1]
    else:
        return str(data)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        df = pd.read_csv(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        columns = df.columns.tolist()
        return render_template('anonymize.html', columns=columns, filename=filename)
    else:
        return "Invalid file format", 400

@app.route('/anonymize', methods=['POST'])
def anonymize():
    column = request.form.get('column')
    filename = request.form.get('filename')
    
    if not column or not filename:
        return "Form data is missing", 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(file_path)
    
    # Ensure the column dtype is appropriate
    df[column] = pd.to_numeric(df[column], errors='coerce')
    
    # Apply partial masking to the selected column
    df[column] = df[column].apply(partial_mask_data)
    
    # Save the anonymized DataFrame to a CSV file
    anonymized_file = 'anonymized_' + filename
    anonymized_file_path = os.path.join(app.config['UPLOAD_FOLDER'], anonymized_file)
    df.to_csv(anonymized_file_path, index=False)
    
    return render_template('download.html', filename=anonymized_file)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
