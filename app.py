import os
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
import pandas as pd
from anonypyx import Anonymizer

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/aaaa')
def index():
    return render_template('kindex.html')

@app.route('/uplload', methods=['POST'])
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
        return render_template('kanonymize.html', columns=columns, filename=filename)
    else:
        return "Invalid file format", 400

@app.route('/annonymize', methods=['POST'])
def anonymize():
    columns = request.form.getlist('columns[]')  # Retrieve selected columns as a list
    filename = request.form.get('filename')
    
    if not columns or not filename:
        return "Form data is missing", 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(file_path)
    
    # Ensure the column dtypes are appropriate
    for column in columns:
        df[column] = pd.to_numeric(df[column], errors='coerce').dropna()
    
    # Calculate the value of k based on the number of records in the DataFrame
    k = min(len(df), 3)  # Set k to the minimum of 3 or the number of records
    
    # Anonymize data using the Mondrian algorithm
    anonymizer = Anonymizer(df, k=k, algorithm="Mondrian", feature_columns=columns)
    anonymized_df = anonymizer.anonymize()
    
    # Save the anonymized DataFrame to a CSV file
    anonymized_file = 'anonymized_' + filename
    anonymized_file_path = os.path.join(app.config['UPLOAD_FOLDER'], anonymized_file)
    anonymized_df.to_csv(anonymized_file_path, index=False)
    
    return render_template('kdownload.html', filename=anonymized_file)

@app.route('/downlload/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)



if __name__ == '__main__':
    app.run(debug=True)
