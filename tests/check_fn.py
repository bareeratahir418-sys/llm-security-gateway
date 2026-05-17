import pandas as pd
df = pd.read_csv('results/evaluation_results.csv')
fn = df[(df['expected']=='BLOCK') & (df['actual']!='BLOCK')]
print(f"False Negatives: {len(fn)}")
print()
for _, row in fn.iterrows():
    print(f"ID {row['id']}: {row['prompt'][:80]}")