import logging
import pickle
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Configure logging
logger = logging.getLogger(__name__)

# Features to use for the model
FEATURE_NAMES = [
    'url_length', 'num_dots', 'num_hyphens', 'num_underscores', 'has_at_symbol',
    'has_ip_address', 'has_suspicious_tld', 'uses_https', 'domain_age', 'num_subdomains',
    'has_suspicious_words', 'path_length'
]

# Create a simple pre-trained model
def create_pretrained_model():
    """
    Create a simple pre-trained random forest model for phishing detection.
    In a production environment, this would be trained on real data and saved.
    
    Returns:
        RandomForestClassifier: Trained model
    """
    # Create a Random Forest model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    
    # Define weights for the features in the model (based on their importance)
    feature_weights = {
        'url_length': 0.6,
        'num_dots': 0.5,
        'num_hyphens': 0.4,
        'num_underscores': 0.3,
        'has_at_symbol': 0.8,
        'has_ip_address': 0.9,
        'has_suspicious_tld': 0.7,
        'uses_https': -0.8,  # negative because HTTPS is a good sign
        'domain_age': -0.85,  # negative because older domains are less suspicious
        'num_subdomains': 0.65,
        'has_suspicious_words': 0.75,
        'path_length': 0.45
    }
    
    return model, feature_weights

# Global model instance
MODEL, FEATURE_WEIGHTS = create_pretrained_model()

def predict_phishing(features):
    """
    Predict whether a URL is phishing based on its features.
    
    Args:
        features (dict): Dictionary of URL features
        
    Returns:
        dict: Dictionary with prediction and confidence
    """
    try:
        # In a real model, we'd use the trained classifier
        # For demonstration purposes, we'll use a simplified heuristic approach
        score = 0
        
        # Calculate weighted score
        for feature_name, weight in FEATURE_WEIGHTS.items():
            if feature_name in features:
                # Convert boolean features to 1 or 0
                feature_value = int(features[feature_name]) if isinstance(features[feature_name], bool) else features[feature_name]
                
                # Apply weight to feature value
                score += weight * feature_value
        
        # Normalize score to a confidence value between 0 and 1
        # using a sigmoid function
        confidence = 1 / (1 + np.exp(-score/5))
        
        # Determine prediction
        prediction = 'phishing' if confidence > 0.5 else 'legitimate'
        
        return {
            'prediction': prediction,
            'confidence': confidence,
            'score': score
        }
        
    except Exception as e:
        logger.error(f"Error in phishing prediction: {e}", exc_info=True)
        # Return a default prediction if something goes wrong
        return {
            'prediction': 'error',
            'confidence': 0.5,
            'score': 0
        }
