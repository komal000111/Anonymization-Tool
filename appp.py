from flask import Flask, render_template, request, send_file
from PIL import Image
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
COMPRESSED_FOLDER = 'compressed'
ALLOWED_EXTENSIONSs = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['COMPRESSED_FOLDER'] = COMPRESSED_FOLDER

def allowedd_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONSs

def get_file_size(filepath):
    return os.path.getsize(filepath) / 1024  # Convert bytes to KB


@app.route('/com')
def comindex():
    return render_template('comindex.html')

@app.route('/compress', methods=['POST'])
def compress():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    compression_level = int(request.form['compression_level'])

    if file.filename == '':
        return "No selected file", 400

    if file and allowedd_file(file.filename):
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        output_path = os.path.join(app.config['COMPRESSED_FOLDER'], file.filename)
        file.save(input_path)

        try:
            with Image.open(input_path) as img:
                img.save(output_path, quality=compression_level)

            original_size_kb = get_file_size(input_path)
            compressed_size_kb = get_file_size(output_path)

            return render_template('comresult.html', 
                                    original_size=original_size_kb, 
                                    compressed_size=compressed_size_kb,
                                    filename=file.filename)
        except Exception as e:
            return f"Error compressing image: {e}", 500
    else:
        return "Invalid file format", 400

@app.route('/dowwnload/<filename>')
def comdownload(filename):
    return send_file(os.path.join(app.config['COMPRESSED_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
