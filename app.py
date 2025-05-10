import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for
from phishing_detector import analyze_url

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

@app.route("/", methods=["GET"])
def index():
    """Main page with URL input form."""
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze a URL for phishing indicators."""
    url = request.form.get("url", "").strip()
    
    if not url:
        flash("Please enter a URL to analyze", "warning")
        return redirect(url_for("index"))
    
    try:
        # Get analysis results from the phishing detector
        logger.debug(f"Analyzing URL: {url}")
        results = analyze_url(url)
        
        return render_template("result.html", url=url, results=results)
    
    except Exception as e:
        logger.error(f"Error analyzing URL: {e}", exc_info=True)
        flash(f"Error analyzing URL: {str(e)}", "danger")
        return redirect(url_for("index"))

@app.route("/about", methods=["GET"])
def about():
    """About page with information on phishing detection."""
    return render_template("index.html", show_about=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
