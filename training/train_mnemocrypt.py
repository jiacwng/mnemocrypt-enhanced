import pandas as pd
import os
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
import joblib
from time import time
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

class_labels = ["non-crypto", "crypto"]
nb_trees = 100
common_dirpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "common")
with open(os.path.join(common_dirpath, "training_set_basenames_listing.txt"), 'r') as file:
    basenames = [line.rstrip() for line in file]
computed_features_dirpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "computed_features")
training_data = pd.DataFrame([])
# Train the classifiers
for basename in basenames:
    curr_binary_data = pd.read_csv(os.path.join(computed_features_dirpath, f"{basename}.csv"))
    # Extend dataframe
    if training_data.empty:
        training_data = curr_binary_data.copy()
    else:
        training_data = pd.concat([training_data, curr_binary_data], ignore_index=True)
X = training_data.drop(columns=['crypto'])  # Drop the 'crypto' column to get features
y = training_data['crypto']
# Drop irrelevant columns from the feature set
X = X.drop(columns=['binary_name', 'function_name'])
# Drop architecture string column (not numerical), but keep is_64bit as a feature
if 'architecture' in X.columns:
    X = X.drop(columns=['architecture'])
# Keep is_64bit as a feature (it's 0 or 1, which is numerical)
# Use SMOTE to oversample the minority class on the combined dataset
oversample = SMOTE()
over_X, over_y = oversample.fit_resample(X, y)
# Build SMOTE SRF model
model = RandomForestClassifier(n_estimators=nb_trees, random_state=42)
# Train the model on the oversampled combined dataset
t = time()
model.fit(over_X, over_y)
print(f"Training time of the model with {nb_trees} trees: {round(time()-t, 3)} s")
# Save the trained model to a file using joblib
model_filepath = os.path.join(common_dirpath, f"trained_mnemocrypt.pkl")
joblib.dump(model, model_filepath)
# Get feature importances
feature_importances = [ round(importance, 3) for importance in model.feature_importances_]
feature_names = [feature.lower() for feature in X.columns]
# Combine feature names with their importances
features_with_importance = list(zip(feature_names, feature_importances))
# Sort the list by importance in descending order
sorted_features = sorted(features_with_importance, key=lambda x: x[1], reverse=True)
# Extract the sorted feature names
sorted_feature_names = [feature for feature, _ in sorted_features]
# Define the filename
filepath = os.path.join(common_dirpath, f"weights_trained_mnemocrypt.txt")
# Write the sorted feature names and their importances with index to the file
with open(filepath, 'w') as file:
    for idx, (feature, importance) in enumerate(sorted_features, start=1):
        file.write(f"{idx}. {feature}: {importance:.4f}\n")
