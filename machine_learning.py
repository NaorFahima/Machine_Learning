import numpy as np
from sklearn.ensemble import RandomForestClassifier as rfc
from sklearn.model_selection import train_test_split
from feature_extraction import UrlInformation
import validators

# Importing dataset
data = np.loadtxt("dataset.csv", delimiter = ",")

# Seperating features and labels
X = data[: , :-1]
y = data[: , -1]

# Seperating training features, testing features, training labels & testing labels
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2)
clf = rfc()
clf.fit(X_train, y_train)
score = clf.score(X_test, y_test)

url = input("Enter url:")
if validators.url(url):
    X_new = UrlInformation(url).data_set
    if X_new == -1:
        print("Phishing Url")
    else:
        X_new = np.array(X_new).reshape(1,-1)
        prediction = clf.predict(X_new)

        if prediction == -1:
            message = "Phishing Url"
        else:
            message = "Legitimate Url"
            
        print(message)
else:
    print("Need to enter valid url")       