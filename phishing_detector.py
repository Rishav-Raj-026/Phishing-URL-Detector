import logging
import re
import requests
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup
from feature_extractor import extract_features
from ml_model import predict_phishing

# Configure logging
logger = logging.getLogger(__name__)

def analyze_url(url):
    """
    Main function to analyze a URL for phishing indicators.
    
    Args:
        url (str): The URL to analyze
    
    Returns:
        dict: Results of the analysis including features and prediction
    """
    # Normalize the URL if needed
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url

    logger.debug(f"Normalized URL for analysis: {url}")
    
    # Extract features from the URL
    features = extract_features(url)
    
    # Get prediction from the ML model
    prediction_results = predict_phishing(features)
    
    # Create the final results dictionary
    results = {
        'features': features,
        'prediction': prediction_results['prediction'],
        'confidence': prediction_results['confidence'],
        'risk_level': get_risk_level(prediction_results['confidence']),
        'explanations': generate_explanations(features, prediction_results)
    }
    
    return results

def get_risk_level(confidence):
    """
    Determine risk level based on confidence score.
    
    Args:
        confidence (float): The confidence score from the model
        
    Returns:
        str: Risk level (Low, Medium, High)
    """
    if confidence < 0.3:
        return "Low"
    elif confidence < 0.7:
        return "Medium"
    else:
        return "High"

def generate_explanations(features, prediction_results):
    """
    Generate human-readable explanations of why URL might be suspicious.
    
    Args:
        features (dict): Extracted features from the URL
        prediction_results (dict): Results from the prediction model
        
    Returns:
        list: List of explanation strings
    """
    explanations = []
    
    # Domain-based explanations
    if features['domain_age'] < 180:  # Less than 6 months old
        explanations.append(f"The domain is relatively new (registered {features['domain_age']} days ago). Phishing sites often use newly registered domains.")
    
    if features['has_at_symbol']:
        explanations.append("URL contains '@' symbol which can be used to hide the actual destination.")
    
    if features['url_length'] > 75:
        explanations.append("The URL is unusually long, which can be a technique to hide the true domain.")
    
    if features['num_subdomains'] > 3:
        explanations.append(f"URL contains {features['num_subdomains']} subdomains, which is suspicious. Phishing URLs often use multiple subdomains.")
    
    if features['has_ip_address']:
        explanations.append("URL uses an IP address instead of a domain name, which is often suspicious.")
    
    if features['has_suspicious_tld']:
        explanations.append(f"The domain uses a TLD ({features['tld']}) that is commonly associated with free or cheap domains, which are popular for phishing.")
    
    if not features['uses_https']:
        explanations.append("The site does not use HTTPS, which is less secure than HTTPS.")
    
    if features['has_suspicious_words']:
        explanations.append("URL contains words commonly used in phishing attempts (like 'secure', 'account', 'update', etc.)")
    
    # If no specific issues but still suspicious
    if not explanations and prediction_results['prediction'] == 'phishing':
        explanations.append("Our machine learning model detected patterns in this URL that match known phishing attempts.")
    
    # If legitimate but with some concerns
    if prediction_results['prediction'] == 'legitimate' and len(explanations) > 0:
        explanations.append("Despite some suspicious characteristics, our model believes this is likely a legitimate URL.")
    
    return explanations
