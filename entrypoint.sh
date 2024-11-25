#!/bin/sh

# Ждем, пока база данных будет готова
while ! nc -z db 5432; do
    echo 'Waiting for database to be ready...'
    sleep 2
done

echo 'Database is ready!'

# Создаем директорию uploads если её нет
mkdir -p /app/uploads
chmod 777 /app/uploads

echo 'Running database migrations...'
# Запускаем скрипт инициализации админа
python init_admin.py

# Проверяем результат выполнения init_admin.py
if [ $? -ne 0 ]; then
    echo 'Failed to initialize admin user'
    exit 1
fi

echo 'Admin user initialized successfully'
echo 'Starting the application...'

# Запускаем основное приложение
exec uvicorn main:app --host 0.0.0.0 --port 8001 --reload
