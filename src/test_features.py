
from feature_extraction import extract_all_features, UCI_FEATURES

url = "https://www.google.com"

try:

    features = extract_all_features(url)

    print("\nPhishGuard Feature Extraction")
    print("=" * 40)

    for feature, value in features.items():
        print(f"{feature}: {value}")

    print("=" * 40)

    print("Total features extracted:", len(features))

except Exception as error:

    print("Error:", error)

missing = set(UCI_FEATURES) - set(features.keys())

print("\nMissing UCI features:")
print(missing)