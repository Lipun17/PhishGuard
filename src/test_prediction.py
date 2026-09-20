from predict import load_model


try:

    model = load_model()

    print("Model loaded successfully!")
    print("Model type:", type(model).__name__)

except Exception as error:

    print("Error:", error)