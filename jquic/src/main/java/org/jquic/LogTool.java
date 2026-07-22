package org.jquic;

import org.slf4j.Logger;
import org.slf4j.MDC;

public class LogTool {
    private final Logger logger;
    
    public LogTool(Logger logger) {
        this.logger = logger;
    }
    
    public void info(String color, String format, Object ... args) {
        // Передаем название ANSI-цвета или ключевое слово
        MDC.put("moduleColor", color); // 35 — это код Magenta (пурпурный) в ANSI

        logger.info(format, args);

        MDC.clear(); // Всегда очищайте MDC в блоке finally!
    }

    public void info(String color, String format, Throwable e, Object ... args) {
        // Передаем название ANSI-цвета или ключевое слово
        MDC.put("moduleColor", color); // 35 — это код Magenta (пурпурный) в ANSI

        logger.info(format, e, args);

        MDC.clear(); // Всегда очищайте MDC в блоке finally!
    }

    public void warn(String color, String format, Object ... args) {
        // Передаем название ANSI-цвета или ключевое слово
        MDC.put("moduleColor", color); // 35 — это код Magenta (пурпурный) в ANSI

        logger.warn(format, args);

        MDC.clear(); // Всегда очищайте MDC в блоке finally!
    }

    public void warn(String color, String format, Throwable e, Object ... args) {
        // Передаем название ANSI-цвета или ключевое слово
        MDC.put("moduleColor", color); // 35 — это код Magenta (пурпурный) в ANSI

        logger.warn(format, e, args);

        MDC.clear(); // Всегда очищайте MDC в блоке finally!
    }

    public void debug(String color, String format, Object ... args) {
        // Передаем название ANSI-цвета или ключевое слово
        MDC.put("moduleColor", color); // 35 — это код Magenta (пурпурный) в ANSI

        logger.debug(format, args);

        MDC.clear(); // Всегда очищайте MDC в блоке finally!
    }

    public void debug(String color, String format, Throwable e, Object ... args) {
        // Передаем название ANSI-цвета или ключевое слово
        MDC.put("moduleColor", color); // 35 — это код Magenta (пурпурный) в ANSI

        logger.debug(format, e, args);

        MDC.clear(); // Всегда очищайте MDC в блоке finally!
    }

    public void error(String color, String format, Object ... args) {
        // Передаем название ANSI-цвета или ключевое слово
        MDC.put("moduleColor", color); // 35 — это код Magenta (пурпурный) в ANSI

        logger.error(format, args);

        MDC.clear(); // Всегда очищайте MDC в блоке finally!
    }

    public void error(String color, String format, Throwable e, Object ... args) {
        // Передаем название ANSI-цвета или ключевое слово
        MDC.put("moduleColor", color); // 35 — это код Magenta (пурпурный) в ANSI

        logger.error(format, e, args);

        MDC.clear(); // Всегда очищайте MDC в блоке finally!
    }

}
