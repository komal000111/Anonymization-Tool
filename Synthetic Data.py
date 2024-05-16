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
def synthesize():
    column = request.form.get('column')
    filename = request.form.get('filename')
    
    if not column or not filename:
        return "Form data is missing", 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(file_path)
    
    # Ensure the column dtype is appropriate
    df[column] = pd.to_numeric(df[column], errors='coerce')
    
    # Generate synthetic data for the selected column
    df[column] = generate_synthetic_data(df[column])
    
    # Save the synthesized DataFrame to a CSV file
    synthetic_file = 'synthetic_' + filename
    synthetic_file_path = os.path.join(app.config['UPLOAD_FOLDER'], synthetic_file)
    df.to_csv(synthetic_file_path, index=False)
    
    return render_template('download.html', filename=synthetic_file)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
