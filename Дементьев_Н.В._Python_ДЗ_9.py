import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Загружаем данные из JSON файла
df = pd.read_json('data/events.json')

# Подсчитаем количество каждого типа события
signature_counts = df['signature'].value_counts()

# Строим график с помощью Seaborn
plt.figure(figsize=(12, 6))
sns.countplot(data=df, y='signature', order=df['signature'].value_counts().index)
plt.title('Распределение типов событий информационной безопасности')
plt.xlabel('Частота')
plt.ylabel('Тип события')
plt.show()