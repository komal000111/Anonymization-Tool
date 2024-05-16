import os
import pandas as pd
import numpy as np
import hashlib
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from anonypyx import Anonymizer

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
        # Mask the middle characters with asterisks
        return data[0] + '*' * (len(data) - 2) + data[-1]
    elif isinstance(data, (int, float)):
        # Mask the entire numeric value with asterisks
        return '****'
    else:
        return str(data)


def swap_data(data):
    # Replace NaN values with a placeholder
    data_filled = data.fillna('****')
    shuffled_index = np.random.permutation(data_filled.index)
    shuffled_data = data_filled.reindex(shuffled_index)

    # Revert placeholder back to NaN
    return shuffled_data.where(data.notnull(), np.nan)

def pseudonymize_data(data):
    if pd.isnull(data):
        return '****'
    else:
        return hashlib.md5(str(data).encode('utf-8')).hexdigest()

def generate_synthetic_data(data):
    # Define probability distributions for each column type
    distributions = {
        'int64': lambda size: np.random.randint(0, 100, size=size),
        'float64': lambda size: np.random.uniform(0, 100, size=size),
        'object': lambda size: np.random.choice(['A', 'B', 'C'], size=size)
    }
    # Get data type of the original column
    data_type = str(data.dtype)
    # Generate synthetic data based on data type
    synthetic_data = distributions.get(data_type, lambda size: None)(len(data))
    return synthetic_data

@app.route('/')
def index():
    return render_template('cindex.html')

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
        return render_template('canonymize.html', columns=columns, filename=filename)
    else:
        return "Invalid file format", 400

@app.route('/anonymize', methods=['POST'])
def anonymize():
    filename = request.form.get('filename')
    technique = request.form.get('technique')
    columns = request.form.getlist('columns')
    
    if not filename or not technique or not columns:
        return "Form data is missing", 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(file_path)
    
    # Ensure the column dtypes are appropriate
    for column in columns:
        df[column] = pd.to_numeric(df[column], errors='coerce')
    
    
    if technique == 'masking':
        for column in columns:
            df[column] = df[column].apply(partial_mask_data)
    elif technique == 'swapping':
        for column in columns:
            df[column] = swap_data(df[column])
    elif technique == 'pseudonymization':
        for column in columns:
            df[column] = df[column].apply(pseudonymize_data)
    elif technique == 'synthetic':
        for column in columns:
            df[column] = generate_synthetic_data(df[column])
    else:
        return "Invalid technique", 400
    
    # Save the anonymized DataFrame to a CSV file
    anonymized_file = 'anonymized_' + filename
    anonymized_file_path = os.path.join(app.config['UPLOAD_FOLDER'], anonymized_file)
    df.to_csv(anonymized_file_path, index=False)
    
    return render_template('cdownload.html', filename=anonymized_file)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
