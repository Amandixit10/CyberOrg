from flask import Flask, request, send_file, render_template
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    org_name = request.form['orgName']
    report_name = request.form['reportName']
    vulnerabilities = eval(request.form['vulnerabilities'])  # Assuming JSON string from client

    # Debug the input values
    date = datetime.now().strftime('%Y-%m-%d')
    print(f"org_name: {org_name}, report_name: {report_name}, date: {date}, vulnerabilities: {vulnerabilities}")

    # Define PDF file path in the project directory
    project_dir = os.path.dirname(os.path.abspath(__file__))
    pdf_file = os.path.join(project_dir, f'{report_name}_report.pdf')

    # Create PDF document
    doc = SimpleDocTemplate(pdf_file, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle(
        name='TitleStyle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=12
    )
    story.append(Paragraph(f"Vulnerability Report", title_style))
    story.append(Spacer(1, 12))

    # Report details
    details_style = styles['Normal']
    story.append(Paragraph(f"Organization: {org_name}", details_style))
    story.append(Paragraph(f"Report Name: {report_name}", details_style))
    story.append(Paragraph(f"Date: {date}", details_style))
    story.append(Spacer(1, 12))

    # Vulnerabilities section
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_text = (
                f"Vulnerability {i}<br/>" +
                f"Severity: {vuln.get('severity', 'N/A')}<br/>" +
                f"Base Score: {vuln.get('base_score', 'N/A')}<br/>" +
                f"Temporal Score: {vuln.get('temporal_score', 'N/A')}<br/>" +
                f"Environmental Score: {vuln.get('environmental_score', 'N/A')}<br/>" +
                f"Description: {vuln.get('description', 'N/A')}<br/>" +
                f"Solution: {vuln.get('solution', 'N/A')}<br/><br/>"
            )
            story.append(Paragraph(vuln_text, styles['Normal']))
    else:
        story.append(Paragraph("No Vulnerabilities Found", styles['Normal']))

    # Build the PDF
    doc.build(story)
    print(f"PDF generated at {pdf_file}")

    # Send the PDF file
    return send_file(pdf_file, as_attachment=True, download_name=f'{report_name}_report.pdf', mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)