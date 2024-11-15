from flask import Flask, render_template, request, send_file, flash
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
from Analyzer import *  # Your existing analyzer class
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import StringIO
import os

app = Flask(__name__)
app.secret_key = 'alpasec'  # Required for flash messages

# Configure upload folder
UPLOAD_FOLDER = Path('uploads')
ALLOWED_EXTENSIONS = {'log', 'txt'}
UPLOAD_FOLDER.mkdir(exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_next_report_number():
    """Get the next report number by checking existing files"""
    reports = []
    for file in os.listdir(app.config['UPLOAD_FOLDER']):
        if file.startswith('Security_Report_'):
            try:
                number = int(file.split('_')[2].split('.')[0])
                reports.append(number)
            except (IndexError, ValueError):
                continue
    return max(reports, default=0) + 1

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files:
            flash('No file selected')
            return render_template('upload.html')
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return render_template('upload.html')
        
        if file and allowed_file(file.filename):
            # Secure the filename and create unique filename with timestamp
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            filepath = app.config['UPLOAD_FOLDER'] / unique_filename
            
            # Save the uploaded file
            file.save(filepath)
            
            try:
                # Analyze the log file
                analyzer = FortiGateLogAnalyzer(logs=filepath)
                report_text = analyzer.generate_text_report()
                
                # Get next report number
                report_number = get_next_report_number()
                
                # Get the requested format from the form
                report_format = request.form.get('format', 'txt')
                
                if report_format == 'txt':
                    # Save and return text report
                    report_filename = f"Security_Report_{report_number:03d}.txt"
                    report_path = app.config['UPLOAD_FOLDER'] / report_filename
                    with open(report_path, 'w') as f:
                        f.write(report_text)
                    
                    return send_file(
                        report_path,
                        mimetype='text/plain',
                        as_attachment=True,
                        download_name=f'Security_Report_{report_number:03d}.txt'
                    )
                
                elif report_format == 'pdf':
                    # Generate and return PDF report
                    report_filename = f"Security_Report_{report_number:03d}.pdf"
                    report_path = app.config['UPLOAD_FOLDER'] / report_filename
                    generate_pdf_report(report_text, report_path)
                    
                    return send_file(
                        report_path,
                        mimetype='application/pdf',
                        as_attachment=True,
                        download_name=f'Security_Report_{report_number:03d}.pdf'
                    )
                
            except Exception as e:
                flash(f'Error analyzing file: {str(e)}')
                return render_template('upload.html')
        else:
            flash('Invalid file type. Please upload a .log or .txt file')
            return render_template('upload.html')
    
    return render_template('upload.html')

def generate_pdf_report(report_text: str, output_path: Path) -> None:
    """Generate a PDF report from the text report that matches text format"""
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=36,  # Reduced margins for better text alignment
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    # Create styles
    styles = getSampleStyleSheet()
    
    # Monospace font style for consistent formatting
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontName='Courier',  # Using monospace font
        fontSize=10,
        spaceAfter=2,
        leading=14,  # Line height
        leftIndent=0
    )
    
    # Style for indented content
    indented_style = ParagraphStyle(
        'CustomIndented',
        parent=normal_style,
        leftIndent=20,
        firstLineIndent=0
    )
    
    # Build the PDF content
    story = []
    
    # Process the text report line by line to maintain exact formatting
    lines = report_text.split('\n')
    
    for line in lines:
        if line.strip():  # Only process non-empty lines
            if line.startswith('    '):  # Indented content
                # Preserve spaces at the start for indentation
                story.append(Paragraph(line.replace(' ', '&nbsp;'), indented_style))
            else:
                # Replace spaces with non-breaking spaces to preserve formatting
                story.append(Paragraph(line.replace(' ', '&nbsp;'), normal_style))
        else:
            # Add empty line
            story.append(Spacer(1, 12))
    
    # Build the PDF
    doc.build(story)

if __name__ == '__main__':
    app.run(debug=True)