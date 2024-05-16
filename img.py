from flask import Flask, render_template, request, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import os
from PIL import Image, ImageDraw

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def change_facial_features(input_image_path, output_image_path):
    # Open the input image
    image = Image.open(input_image_path)
    
    # Create a copy of the image for manipulation
    modified_image = image.copy()
    
    # Get the image dimensions
    width, height = image.size
    
    # Define the region of the mouth
    mouth_region = (int(width * 0.2), int(height * 0.6), int(width * 0.8), int(height * 0.8))
    
    # Crop the mouth region from the original image
    mouth = image.crop(mouth_region)
    
    # Paste the mouth region to a new position
    new_mouth_position = (int(width * 0.2), int(height * 0.5))
    modified_image.paste(mouth, new_mouth_position)
    
    # Blend the pasted mouth region with the surrounding pixels for a more realistic effect
    alpha = 0.5  # Adjust the alpha value as needed
    modified_image.paste(mouth, new_mouth_position, mouth.convert('RGBA'))
    
    # Save the modified image
    modified_image.save(output_image_path)

@app.route('/')
def index():
    return render_template('igindex.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        output_filename = 'anonymized_' + filename
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        change_facial_features(input_path, output_path)
        return redirect(url_for('download_file', filename=output_filename))
    else:
        return redirect(request.url)

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
