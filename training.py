from sklearn.metrics import accuracy_score
import numpy as np
from sklearn import ensemble
import joblib

training_data = np.genfromtxt("./test4.csv", delimiter=',' , dtype = np.int32 )
np.random.shuffle(training_data)

inputs = training_data[:,:-1] #train
outputs = training_data[:,-1] #test

training_inputs = inputs[: 15000]
training_outputs = outputs[: 15000]
testing_inputs = inputs[15000 :]
testing_outputs = outputs[15000 :]

classifier = ensemble.RandomForestClassifier(n_estimators=20)
classifier.fit(training_inputs, training_outputs)
predictions = classifier.predict(testing_inputs)
accuracy = 100.0 * accuracy_score(testing_outputs,predictions)
print("RandomForest accuracy = ", str(accuracy))

# final test
# url = 'https://youtube.com'
# feature = FeatureExtraction(url)
# feature_score = np.array([feature.run_process()])
# print(feature_score)
# prediction = classifier.predict(feature_score)
# print(prediction)

# model save in pkl format
joblib.dump(classifier, 'ML_model.pkl')