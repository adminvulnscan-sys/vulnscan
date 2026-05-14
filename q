[1mdiff --git a/app.py b/app.py[m
[1mindex 344fcf9..7ed466b 100644[m
[1m--- a/app.py[m
[1m+++ b/app.py[m
[36m@@ -1230,7 +1230,7 @@[m [mclass ReportePDF(FPDF):[m
             self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')[m
 [m
 def crear_pdf(dominio, resultados):[m
[31m-    resultados = [r.replace('\u2014', '-').replace('\u2013', '-').replace('\u2019', "'").replace('\u201c', '"').replace('\u201d', '"') for r in resultados][m
[32m+[m[32m    resultados = [r.replace('\u2014', '-').replace('\u2013', '-').replace('\u2019', "'").replace('\u201c', '"').replace('\u201d', '"').replace('á', 'a').replace('é', 'e').replace('í', 'i').replace('ó', 'o').replace('ú', 'u').replace('Á', 'A').replace('É', 'E').replace('Í', 'I').replace('Ó', 'O').replace('Ú', 'U').replace('ñ', 'n').replace('Ñ', 'N').replace('→', '->').replace('–', '-').replace('•', '-') for r in resultados][m
     # --- FIX DUPLICADOS: Eliminamos cualquier resultado repetido ---[m
     resultados_unicos = [][m
     for r in resultados:[m
[36m@@ -1349,8 +1349,12 @@[m [mdef crear_pdf(dominio, resultados):[m
     fallos = [r for r in resultados if "🔴" in r or "🚨" in r or "⚠️" in r or "ℹ️" in r][m
     if fallos:[m
         for malo in fallos:[m
[31m-            texto_limpio = malo.replace('🔴', '[CRITICO]').replace('🚨', '[ALERTA]').replace('⚠️', '[AVISO]').replace('ℹ️', '[INFO]')[m
[31m-            [m
[32m+[m[32m            texto_limpio = malo.replace('🔴 **', '').replace('🚨 **', '').replace('⚠️ **', '').replace('ℹ️ **', '').replace('**', '').replace('`', '')[m
[32m+[m[32m            # Quitar prefijos redundantes[m
[32m+[m[32m            for prefijo in ['Aviso: ', 'Alerta: ', 'Info: ', 'Critico: ', 'CRITICO: ', 'ALERTA: ', 'AVISO: ', 'INFO: ']:[m
[32m+[m[32m                if texto_limpio.startswith(prefijo):[m
[32m+[m[32m                    texto_limpio = texto_limpio[len(prefijo):][m
[32m+[m[41m                        [m
             # 1. Imprimimos el fallo técnico en negrita[m
             pdf.set_font("Helvetica", "B", 11)[m
             pdf.multi_cell(0, 6, texto_limpio)[m
