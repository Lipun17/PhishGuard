from feature_extraction import extract_basic_features


test_urls = [
    "https://www.google.com",
    "http://192.168.1.1/login@verify-account"
]


for url in test_urls:

    print("\nURL:", url)

    features = extract_basic_features(url)

    for feature, value in features.items():
        print(f"{feature}: {value}")