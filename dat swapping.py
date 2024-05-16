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

def swap_data(data):
    # Replace NaN values with a placeholder
    data_filled = data.fillna('****')
    # Shuffle the data
    shuffled_data = np.random.permutation(data_filled)
    # Convert back to original dtype
    shuffled_data = pd.Series(shuffled_data, index=data_filled.index)
    # Revert placeholder back to NaN
    return shuffled_data.where(data.notnull(), np.nan)

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
def swap():
    column = request.form.get('column')
    filename = request.form.get('filename')
    
    if not column or not filename:
        return "Form data is missing", 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(file_path)
    
    # Ensure the column dtype is appropriate
    df[column] = pd.to_numeric(df[column], errors='coerce')
    
    # Apply swapping to the selected column
    df[column] = swap_data(df[column])
    
    # Save the swapped DataFrame to a CSV file
    swapped_file = 'swapped_' + filename
    swapped_file_path = os.path.join(app.config['UPLOAD_FOLDER'], swapped_file)
    df.to_csv(swapped_file_path, index=False)
    
    return render_template('download.html', filename=swapped_file)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
