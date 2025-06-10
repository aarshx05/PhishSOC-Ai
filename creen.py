import time
import os
import tensorflow as tf
import numpy as np
import hashlib
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, WebDriverException
from PIL import Image
from tensorflow.keras.preprocessing import image

def sanitize_url(url):
    """Creates a sanitized version of the URL suitable for a folder name."""
    return hashlib.md5(url.encode()).hexdigest()

def capture_screenshot(url, driver_path, base_output_dir):
    """Captures a screenshot of the given URL and saves it in ./ssout/hashed_url/"""
    
    sanitized_name = sanitize_url(url)
    output_dir = os.path.join(base_output_dir, sanitized_name)
    os.makedirs(output_dir, exist_ok=True)
    output_image_path = os.path.join(output_dir, "screenshot.png")
    
    service = Service(driver_path)
    options = webdriver.ChromeOptions()
    options.headless = True
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    driver = webdriver.Chrome(service=service, options=options)

    try:
        driver.set_page_load_timeout(2000)
        driver.get(url)
        time.sleep(10)

        driver.save_screenshot(output_image_path)
        screenshot_saved = os.path.exists(output_image_path)
    
    except (TimeoutException, WebDriverException):
        output_image_path = None
        screenshot_saved = False
    
    finally:
        driver.quit()
    
    return output_image_path, screenshot_saved

def preprocess_image(image_path):
    """Prepares the image for classification using ResNet50."""
    img = image.load_img(image_path, target_size=(224, 224))
    img_array = image.img_to_array(img)
    img_array = np.expand_dims(img_array, axis=0)
    img_array = tf.keras.applications.resnet50.preprocess_input(img_array)
    return img_array

def predict_phishing(image_path):
    """Uses ResNet50 to classify a screenshot and determine phishing risk."""
    model = tf.keras.applications.ResNet50(weights='imagenet')
    img_array = preprocess_image(image_path)
    predictions = model.predict(img_array)
    decoded_predictions = tf.keras.applications.resnet50.decode_predictions(predictions)
    
    predicted_label = decoded_predictions[0][0][1]
    confidence = decoded_predictions[0][0][2] * 100
    
    phishing_indicators = ["phishing", "login", "account", "password", "security", "verify"]
    
    if confidence < 50:
        result = "Probably phishing (low confidence)"
    elif any(indicator in predicted_label.lower() for indicator in phishing_indicators):
        result = "Warning: This may be a phishing site!"
    else:
        result = "This appears to be a legitimate site."
    
    return result, predicted_label, confidence

def log_results(url, result, predicted_label, confidence, output_dir):
    """Logs analysis results to results.txt inside each URL's directory."""
    log_path = os.path.join(output_dir, "results.txt")
    
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write(f"URL: {url}\n")
        log_file.write(f"Prediction: {predicted_label} (Confidence: {confidence:.2f}%)\n")
        log_file.write(f"Phishing Status: {result}\n")
        log_file.write("=" * 60 + "\n")
    
    return log_path

def process_links_from_file(file_path, driver_path, base_output_dir):
    """Reads URLs from file, captures screenshots, analyzes them, and logs results."""
    
    if not os.path.exists(file_path):
        return {"error": f"{file_path} not found"}
    
    with open(file_path, 'r') as file:
        urls = [url.strip() for url in file.readlines()]
    
    results = []
    for url in urls:
        output_image_path, screenshot_saved = capture_screenshot(url, driver_path, base_output_dir)
        
        if not screenshot_saved:
            results.append({"url": url, "error": "Screenshot not saved"})
            continue
        
        result, predicted_label, confidence = predict_phishing(output_image_path)
        log_path = log_results(url, result, predicted_label, confidence, os.path.dirname(output_image_path))
        
        results.append({
            "url": url,
            "screenshot_path": output_image_path,
            "prediction": predicted_label,
            "confidence": confidence,
            "phishing_status": result,
            "log_path": log_path
        })
    
    return results


