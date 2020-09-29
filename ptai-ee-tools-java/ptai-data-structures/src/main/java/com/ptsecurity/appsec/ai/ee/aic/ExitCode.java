package com.ptsecurity.appsec.ai.ee.aic;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ExitCode {
    @Getter
    protected Integer code;
    @Getter
    protected String description;

    private ExitCode(Integer code, String description) {
        this.code = code;
        this.description = description;
    }

    // 0       Успешное выполнение
    public static final ExitCode CODE_SUCCESS = new ExitCode(0, "Success");
    // -1      Приложение уже запущено
    public static final ExitCode CODE_ERROR_ALREADY_STARTED = new ExitCode(-1, "Application already started");
    // -2      Ошибка запуска дочернего процесса
    public static final ExitCode CODE_ERROR_CHILD_PROCESS = new ExitCode(-2, "Child process start failed");
    // 2       Директория для сканирования не найдена
    public static final ExitCode CODE_ERROR_SCAN_FOLDER = new ExitCode(2, "Scan folder not found");
    // 3       Проблема с лицензией
    public static final ExitCode CODE_ERROR_LICENSE = new ExitCode(3, "License problem");
    // 4       Не найден проект для сканирования
    public static final ExitCode CODE_ERROR_PROJECT_NOT_FOUND = new ExitCode(4, "Project not found");
    // 5       Ошибки в настройках проекта
    public static final ExitCode CODE_ERROR_PROJECT_SETTINGS = new ExitCode(5, "Project settings error");
    // 6       В логах AI есть не критические ошибки. Результат можно отобразить пользователю, но на ошибки стоит обратить внимание.
    public static final ExitCode CODE_WARNING = new ExitCode(6, "Warnings were generated during scan");
    // 7       Ошибка отправки отчёта на почту
    public static final ExitCode CODE_ERROR_EMAIL = new ExitCode(7, "Report email failed");
    // 8       Некорректный путь к файлу настроек
    public static final ExitCode CODE_ERROR_SETTINGS_PATH = new ExitCode(8, "Settings file path incorrect");
    // 9       Некорректный путь к папке отчётов
    public static final ExitCode CODE_ERROR_REPORT_FOLDER = new ExitCode(9, "Reports folder path incorrect");
    // 10      Сработала политика безопасности
    public static final ExitCode CODE_FAILED = new ExitCode(10, "AST policy assessment failed");
    // 11      Некорректные настройки отчётов
    public static final ExitCode CODE_ERROR_REPORT_SETTINGS = new ExitCode(11, "Incorrect report settings");
    // 12      Не найден сертификат агентом
    public static final ExitCode CODE_ERROR_CERTIFICATE_NOTFOUND = new ExitCode(12, "Agent certificate not found");
    // 13      Сканирование было удалено
    public static final ExitCode CODE_ERROR_SCAN_DELETED = new ExitCode(13, "Scan was deleted");
    // 14      Ошибка авторизации авточек
    public static final ExitCode CODE_ERROR_AUTOCHECK_AUTZ = new ExitCode(14, "Autocheck authorization failed");
    // 15      Некорректные настройки прокси
    public static final ExitCode CODE_ERROR_PROXY = new ExitCode(15, "Incorrect proxy settings");
    // 16      Некорректный хост для проверки
    public static final ExitCode CODE_ERROR_AUTOCHECK_URL = new ExitCode(16, "Incorect autocheck host URL");
    // 17      Ошибка в политике безопасности
    public static final ExitCode CODE_ERROR_POLICY = new ExitCode(17, "AST policy incorrect");
    // 18      Получена критическая ошибка ядра
    public static final ExitCode CODE_ERROR_KERNEL_CRITICAL = new ExitCode(18, "Critical kernel error");
    // 19      Ядро не найдено
    public static final ExitCode CODE_ERROR_KERNEL_NOTFOUND = new ExitCode(19, "Kernel not found");
    // 20      Ошибка во время загрузки исходников с сервера
    public static final ExitCode CODE_ERROR_SRC_DOWNLOAD = new ExitCode(20, "Sources download failed");
    // 21      Таймаут сообщения обновления жизни агента (агент сигнализирует о том, что он живой, этот код говорит о том, что он подвис и не успел это сделать)
    public static final ExitCode CODE_ERROR_HEARTBEAT = new ExitCode(21, "Agent heartbeat timeout");
    // 22      Ошибка в процессе обновления
    public static final ExitCode CODE_ERROR_UPDATE = new ExitCode(22, "Update failed");
    // 23      Неверный пароль от сертификата
    public static final ExitCode CODE_ERROR_PASSWORD_INCORRECT = new ExitCode(23, "Incorrect certificate password");
    // 24      Не найден серверный сертификат
    public static final ExitCode CODE_ERROR_SERVER_CERTIFICATE_NOTFOUND = new ExitCode(24, "Server certificate not found");
    // 100     Сканирование отменено (CTRL-C)
    public static final ExitCode CODE_ERROR_TERMINATED = new ExitCode(100, "Scan terminated (Ctrl-C)");
    // 1000    Неопознанная ошибка
    public static final ExitCode CODE_UNKNOWN_ERROR = new ExitCode(1000, "Unknown error");
    // 2000    Policy not defined
    public static final ExitCode CODE_POLICY_NOT_DEFINED = new ExitCode(2000, "AST policy not defined");

    public static Map<Integer, String> CODES = new HashMap<>();

    static {
        Arrays.asList(
                CODE_SUCCESS, CODE_ERROR_ALREADY_STARTED, CODE_ERROR_CHILD_PROCESS,
                CODE_ERROR_SCAN_FOLDER, CODE_ERROR_LICENSE, CODE_ERROR_PROJECT_NOT_FOUND,
                CODE_ERROR_PROJECT_SETTINGS, CODE_WARNING, CODE_ERROR_EMAIL,
                CODE_ERROR_SETTINGS_PATH, CODE_ERROR_REPORT_FOLDER, CODE_FAILED,
                CODE_ERROR_REPORT_SETTINGS, CODE_ERROR_CERTIFICATE_NOTFOUND, CODE_ERROR_SCAN_DELETED,
                CODE_ERROR_AUTOCHECK_AUTZ, CODE_ERROR_PROXY, CODE_ERROR_AUTOCHECK_URL,
                CODE_ERROR_POLICY, CODE_ERROR_KERNEL_CRITICAL, CODE_ERROR_KERNEL_NOTFOUND,
                CODE_ERROR_SRC_DOWNLOAD, CODE_ERROR_HEARTBEAT, CODE_ERROR_UPDATE,
                CODE_ERROR_PASSWORD_INCORRECT, CODE_ERROR_SERVER_CERTIFICATE_NOTFOUND, CODE_ERROR_TERMINATED,
                CODE_UNKNOWN_ERROR, CODE_POLICY_NOT_DEFINED).stream().forEach(c -> CODES.put(c.code, c.description));
    }
}
