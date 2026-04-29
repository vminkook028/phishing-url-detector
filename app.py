from flask import Flask, render_template, request, jsonify
import re
import math
from urllib.parse import urlparse
import urllib.request

app = Flask(__name__)

# =============================================
# FEATURE EXTRACTION - URL se features nikalte hain
# =============================================

def get_url_length(url):
    return len(url)

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_underscores(url):
    return url.count('_')

def count_slashes(url):
    return url.count('/')

def count_at_symbols(url):
    return url.count('@')

def count_question_marks(url):
    return url.count('?')

def count_equal_signs(url):
    return url.count('=')

def count_ampersands(url):
    return url.count('&')

def has_ip_address(url):
    """URL mein IP address hai ya nahi"""
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    return 1 if re.search(ip_pattern, url) else 0

def has_https(url):
    return 1 if url.startswith('https') else 0

def get_domain_length(url):
    try:
        parsed = urlparse(url)
        return len(parsed.netloc)
    except:
        return 0

def count_subdomains(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        parts = domain.split('.')
        return max(0, len(parts) - 2)
    except:
        return 0

def has_suspicious_words(url):
    suspicious = ['login', 'signin', 'verify', 'update', 'secure', 'account',
                  'banking', 'confirm', 'password', 'credential', 'free', 'lucky',
                  'winner', 'click', 'prize', 'bonus', 'paypal', 'ebay', 'amazon']
    url_lower = url.lower()
    count = sum(1 for word in suspicious if word in url_lower)
    return count

def get_entropy(url):
    """URL ki randomness measure karta hai"""
    if not url:
        return 0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    length = len(url)
    entropy = -sum((f/length) * math.log2(f/length) for f in freq.values())
    return round(entropy, 4)

def has_redirect(url):
    return 1 if '//' in url[7:] else 0

def has_shortener(url):
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
                  'buff.ly', 'adf.ly', 'tiny.cc', 'cutt.ly']
    return 1 if any(s in url.lower() for s in shorteners) else 0

def get_path_length(url):
    try:
        parsed = urlparse(url)
        return len(parsed.path)
    except:
        return 0

def count_digits_in_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        return sum(1 for c in domain if c.isdigit())
    except:
        return 0

# =============================================
# SCORING ALGORITHM - AI-style weighted scoring
# =============================================

def calculate_phishing_score(url):
    """
    Weighted scoring system - phishing probability calculate karta hai
    """
    score = 0
    max_score = 100
    reasons = []
    safe_points = []

    # URL Length check
    url_len = get_url_length(url)
    if url_len > 75:
        score += 15
        reasons.append(f"URL is very long ({url_len} characters)")
    elif url_len > 54:
        score += 7
        reasons.append(f"URL is quite long ({url_len} characters)")
    else:
        safe_points.append("URL length is normal")

    # IP Address
    if has_ip_address(url):
        score += 20
        reasons.append("URL contains an IP address instead of a domain")
    
    # HTTPS check
    if not has_ip_address(url):
        if not has_https(url):
            score += 10
            reasons.append("No HTTPS - insecure connection")
        else:
            safe_points.append("HTTPS is enabled")

    # Suspicious words
    susp_count = has_suspicious_words(url)
    if susp_count >= 3:
        score += 20
        reasons.append(f"{susp_count} suspicious words found (login, verify, secure, etc.)")
    elif susp_count >= 1:
        score += 10
        reasons.append(f"{susp_count} suspicious word(s) found")
    else:
        safe_points.append("No suspicious words found")

    # Hyphens in domain
    parsed = urlparse(url)
    domain_hyphens = parsed.netloc.count('-')
    if domain_hyphens >= 3:
        score += 12
        reasons.append(f"Too many hyphens in domain ({domain_hyphens})")
    elif domain_hyphens >= 1:
        score += 5
        reasons.append(f"Domain contains {domain_hyphens} hyphen(s)")

    # Subdomains
    subdomain_count = count_subdomains(url)
    if subdomain_count >= 3:
        score += 15
        reasons.append(f"Too many subdomains ({subdomain_count})")
    elif subdomain_count == 2:
        score += 7
        reasons.append("Multiple subdomains detected")

    # URL shortener
    if has_shortener(url):
        score += 15
        reasons.append("URL shortener detected - real destination is hidden")

    # @ symbol
    if count_at_symbols(url) > 0:
        score += 20
        reasons.append("@ symbol found in URL - browser may ignore the real address")

    # Double slash redirect
    if has_redirect(url):
        score += 10
        reasons.append("Redirect detected (//) - suspicious pattern")

    # High entropy (random-looking URLs)
    entropy = get_entropy(url)
    if entropy > 4.2:
        score += 8
        reasons.append(f"URL appears very random/complex (entropy: {entropy})")

    # Digits in domain
    domain_digits = count_digits_in_domain(url)
    if domain_digits >= 3:
        score += 8
        reasons.append(f"Too many digits in domain ({domain_digits})")

    # Too many query params
    if count_equal_signs(url) > 4:
        score += 5
        reasons.append("Too many query parameters")

    # Cap the score at 100
    score = min(score, 100)

    return score, reasons, safe_points

def get_verdict(score):
    if score >= 70:
        return "PHISHING", "danger", "🚨"
    elif score >= 45:
        return "SUSPICIOUS", "warning", "⚠️"
    elif score >= 20:
        return "LOW RISK", "caution", "🔍"
    else:
        return "SAFE", "safe", "✅"

# =============================================
# FLASK ROUTES
# =============================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL enter karo please'}), 400

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    score, reasons, safe_points = calculate_phishing_score(url)
    verdict, level, emoji = get_verdict(score)

    # Feature details for display
    parsed = urlparse(url)
    features = {
        'URL Length': get_url_length(url),
        'Domain': parsed.netloc or 'N/A',
        'HTTPS': 'Yes ✅' if has_https(url) else 'No ❌',
        'Has IP Address': 'Yes ❌' if has_ip_address(url) else 'No ✅',
        'Subdomains': count_subdomains(url),
        'Suspicious Words': has_suspicious_words(url),
        'URL Shortener': 'Yes ❌' if has_shortener(url) else 'No ✅',
        'Entropy Score': get_entropy(url),
        'Dots in URL': count_dots(url),
        'Hyphens': count_hyphens(url),
    }

    return jsonify({
        'url': url,
        'score': score,
        'verdict': verdict,
        'level': level,
        'emoji': emoji,
        'reasons': reasons,
        'safe_points': safe_points,
        'features': features
    })

if __name__ == '__main__':
    app.run(debug=True)