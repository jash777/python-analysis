from flask import Flask, render_template, request, send_file, flash, jsonify, make_response
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
import requests
from typing import Dict, Any
from ai_agent import SecurityAIAgent
import threading
import uuid
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Verify the environment variable is set correctly
host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
print(f"Using Ollama host: {host}")

# Make sure the environment variable is set correctly
os.environ["OLLAMA_HOST"] = host

app = Flask(__name__)
app.secret_key = 'alpasec'  # Required for flash messages

# Configure folders
UPLOAD_FOLDER = Path('uploads')
AI_REPORTS_FOLDER = Path('ai_reports')  # New folder for AI reports
ALLOWED_EXTENSIONS = {'log', 'txt'}

# Create necessary folders
UPLOAD_FOLDER.mkdir(exist_ok=True)
AI_REPORTS_FOLDER.mkdir(exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['AI_REPORTS_FOLDER'] = AI_REPORTS_FOLDER

# Initialize the AI agent
ai_agent = SecurityAIAgent()

# Store AI analysis jobs with serializable data
ai_analysis_jobs = {}

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
        if 'file' not in request.files:
            flash('No file selected')
            return render_template('upload.html')
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return render_template('upload.html')
        
        if file and allowed_file(file.filename):
            # Generate unique ID for this analysis
            analysis_id = str(uuid.uuid4())
            
            # Save and analyze file
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            filepath = str(app.config['UPLOAD_FOLDER'] / unique_filename)  # Convert to string
            
            file.save(filepath)
            
            try:
                # Generate normal report
                analyzer = FortiGateLogAnalyzer(logs=filepath)
                report_text = analyzer.generate_text_report()
                
                # If AI analysis is requested, start it in background
                if request.form.get('request_ai_analysis'):
                    ai_analysis_jobs[analysis_id] = {
                        'status': 'processing',
                        'progress': 0,
                        'filepath': filepath,
                        'report_text': report_text,
                        'timestamp': timestamp
                    }
                    
                    # Start AI analysis in background
                    thread = threading.Thread(
                        target=process_ai_analysis,
                        args=(analysis_id, report_text)
                    )
                    thread.start()
                
                # Return normal report
                response = make_response(report_text)
                response.headers['Content-Type'] = 'text/plain'
                response.headers['Content-Disposition'] = f'attachment; filename=Security_Report_{timestamp}.txt'
                
                if request.form.get('request_ai_analysis'):
                    response.headers['X-Analysis-ID'] = analysis_id
                
                return response
                
            except Exception as e:
                flash(f'Error analyzing file: {str(e)}')
                return render_template('upload.html')
                
    return render_template('upload.html')

def process_ai_analysis(analysis_id: str, raw_logs: str):
    """Process AI analysis in background"""
    try:
        ai_agent = SecurityAIAgent()
        
        # Update progress to 30%
        ai_analysis_jobs[analysis_id]['progress'] = 30
        
        # Get AI analysis using the multi-agent system
        ai_report = ai_agent.analyze_logs(raw_logs)
        
        # Update progress to 90%
        ai_analysis_jobs[analysis_id]['progress'] = 90
        
        # Save AI report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ai_report_filename = f"AI_Security_Report_{timestamp}.txt"
        report_path = str(app.config['AI_REPORTS_FOLDER'] / ai_report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(ai_report)
        
        # Update job status
        ai_analysis_jobs[analysis_id].update({
            'status': 'completed',
            'progress': 100,
            'report_path': report_path,
            'report_filename': ai_report_filename
        })
        
    except Exception as e:
        ai_analysis_jobs[analysis_id].update({
            'status': 'failed',
            'error': str(e)
        })

@app.route('/ai-analysis-status/<analysis_id>')
def get_ai_analysis_status(analysis_id):
    """Get the status of an AI analysis job"""
    if analysis_id not in ai_analysis_jobs:
        return jsonify({'status': 'not_found'}), 404
    
    # Create a serializable copy of the job data
    job_data = {
        'status': ai_analysis_jobs[analysis_id]['status'],
        'progress': ai_analysis_jobs[analysis_id]['progress']
    }
    
    if 'error' in ai_analysis_jobs[analysis_id]:
        job_data['error'] = ai_analysis_jobs[analysis_id]['error']
    
    if 'report_filename' in ai_analysis_jobs[analysis_id]:
        job_data['report_filename'] = ai_analysis_jobs[analysis_id]['report_filename']
    
    return jsonify(job_data)

@app.route('/download-ai-report/<filename>')
def download_ai_report(filename):
    """Download an AI analysis report by filename"""
    try:
        report_path = app.config['AI_REPORTS_FOLDER'] / filename
        if not report_path.exists():
            return jsonify({'error': 'Report not found'}), 404
        
        return send_file(
            report_path,
            mimetype='text/plain',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ai-reports')
def list_ai_reports():
    """List all available AI reports"""
    try:
        reports = []
        for file in os.listdir(app.config['AI_REPORTS_FOLDER']):
            if file.startswith('AI_Security_Report_'):
                file_path = app.config['AI_REPORTS_FOLDER'] / file
                reports.append({
                    'filename': file,
                    'created': datetime.fromtimestamp(os.path.getctime(str(file_path))).strftime('%Y-%m-%d %H:%M:%S'),
                    'size': os.path.getsize(str(file_path)) // 1024  # Size in KB
                })
        return jsonify(reports)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

def save_ai_report(ai_analysis: str) -> str:
    """Save AI analysis report and return filename"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"AI_Security_Report_{timestamp}.txt"
    report_path = app.config['AI_REPORTS_FOLDER'] / filename
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(ai_analysis)
    
    return filename

@app.route('/analyze', methods=['POST'])
def analyze_logs():
    try:
        # Get the normal report first
        normal_report = generate_normal_report(request.files['file'])
        
        # Pass the normal report to AI analysis
        ai_agent = SecurityAIAgent()
        ai_analysis = ai_agent.analyze_report(normal_report)
        
        # Save and return the AI analysis
        save_ai_report(ai_analysis)
        return jsonify({'status': 'success', 'report': ai_analysis})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def generate_normal_report(file):
    """Generate a normal report from uploaded file"""
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = str(app.config['UPLOAD_FOLDER'] / f"{timestamp}_{filename}")
    
    file.save(filepath)
    analyzer = FortiGateLogAnalyzer(logs=filepath)
    return analyzer.generate_text_report()

if __name__ == '__main__':
    app.run(debug=True)