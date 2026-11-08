"""Small, escaped Markdown renderer for email. No remote assets or raw HTML."""
import html
import re


def inline(text: str) -> str:
    parts = []
    # Code spans take precedence: Markdown inside CLI text stays literal.
    pattern = r'`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^\s)]+)\)'
    end = 0
    for match in re.finditer(pattern, text):
        parts.append(html.escape(text[end:match.start()]))
        if match[1] is not None:
            parts.append('<code style="font-family:Consolas,monospace;font-size:13px;'
                         'background:#eef2f6;color:#17365d;padding:2px 5px;'
                         'border-radius:4px;overflow-wrap:anywhere">'
                         + html.escape(match[1]) + '</code>')
        elif match[2] is not None:
            parts.append('<strong>' + html.escape(match[2]) + '</strong>')
        else:
            label, url = html.escape(match[3]), match[4]
            if re.match(r'^https?://', url, re.IGNORECASE):
                parts.append('<a style="color:#1665a8" href="'
                             + html.escape(url, quote=True) + '">' + label + '</a>')
            else:
                # Workspace links cannot be opened by the recipient as web URLs.
                parts.append(label + ' (' + html.escape(url) + ')')
        end = match.end()
    parts.append(html.escape(text[end:]))
    return ''.join(parts)


def table_cells(line: str) -> list[str]:
    # A pipe inside a CLI code span is not a table separator.
    cells, cell, in_code = [], [], False
    text = line.strip()[1:-1]
    for char in text:
        if char == '`':
            in_code = not in_code
        if char == '|' and not in_code:
            cells.append(''.join(cell).strip())
            cell = []
        else:
            cell.append(char)
    cells.append(''.join(cell).strip())
    return cells


def render_report(markdown: str, report_id: str = '') -> str:
    blocks, paragraph, code, rows = [], [], None, []
    list_tag = None

    def flush_paragraph():
        if paragraph:
            blocks.append('<p style="margin:0 0 14px;line-height:1.75">'
                          + inline(' '.join(paragraph)) + '</p>')
            paragraph.clear()

    def close_list():
        nonlocal list_tag
        if list_tag:
            blocks.append('</' + list_tag + '>')
            list_tag = None

    def flush_table():
        if not rows:
            return
        blocks.append('<table role="table" cellpadding="0" cellspacing="0" '
                      'style="border-collapse:collapse;width:100%;margin:16px 0 22px;font-size:13px">')
        for index, row in enumerate(rows):
            tag = 'th' if index == 0 else 'td'
            background = '#e9f0f8' if index == 0 else ('#f8fafc' if index % 2 == 0 else '#ffffff')
            blocks.append('<tr>' + ''.join(
                '<' + tag + (' scope="col"' if index == 0 else '')
                + ' style="border:1px solid #d7e0ea;padding:11px 12px;text-align:left;'
                  'vertical-align:top;line-height:1.6;background:' + background + '">'
                + inline(cell) + '</' + tag + '>' for cell in row) + '</tr>')
        blocks.append('</table>')
        rows.clear()

    def code_block(lines):
        blocks.append('<pre style="margin:14px 0 22px;padding:16px;background:#f3f6fa;'
                      'border:1px solid #d7e0ea;border-left:4px solid #49769e;'
                      'color:#203047;white-space:pre-wrap;word-wrap:break-word;'
                      'overflow-wrap:anywhere;font:12px/1.65 Consolas,monospace">'
                      + html.escape('\n'.join(lines)) + '</pre>')

    for line in markdown.splitlines():
        if line == '<!-- FULL-SANITIZED-EVIDENCE -->':
            continue
        if line.startswith('```'):
            flush_paragraph()
            close_list()
            flush_table()
            if code is None:
                code = []
            else:
                code_block(code)
                code = None
            continue
        if code is not None:
            code.append(line)
            continue
        if line.strip().startswith('|') and line.strip().endswith('|'):
            flush_paragraph()
            close_list()
            cells = table_cells(line)
            if not all(re.fullmatch(r':?-{3,}:?', cell) for cell in cells):
                rows.append(cells)
            continue
        flush_table()
        heading = re.match(r'^(#{1,6})\s+(.+)$', line)
        item = re.match(r'^\s*(?:([-*])|\d+\.)\s+(.+)$', line)
        if heading:
            flush_paragraph()
            close_list()
            level = len(heading[1])
            size = {1: 25, 2: 20, 3: 16}.get(level, 14)
            border = 'border-bottom:2px solid #e4ebf3;padding-bottom:10px;' if level <= 2 else ''
            blocks.append(f'<h{level} style="font-size:{size}px;color:#123b65;'
                          f'line-height:1.4;margin:26px 0 14px;{border}">'
                          + inline(heading[2]) + f'</h{level}>')
        elif item:
            flush_paragraph()
            wanted = 'ul' if item[1] else 'ol'
            if list_tag != wanted:
                close_list()
                list_tag = wanted
                blocks.append('<' + wanted + ' style="padding-left:24px;margin:10px 0 18px">')
            blocks.append('<li style="padding-left:3px;margin:8px 0;line-height:1.75">'
                          + inline(item[2]) + '</li>')
        elif line.startswith('> '):
            flush_paragraph()
            close_list()
            blocks.append('<div style="padding:14px 16px;margin:16px 0;background:#fff8e7;'
                          'border-left:4px solid #d7a126;color:#684b0b;line-height:1.7">'
                          + inline(line[2:]) + '</div>')
        elif not line.strip():
            flush_paragraph()
            close_list()
        else:
            close_list()
            paragraph.append(line.strip())
    flush_paragraph()
    close_list()
    flush_table()
    if code is not None:
        code_block(code)
    title = html.escape(report_id or 'Báo cáo điều tra mạng')
    return ('<!doctype html><html lang="vi"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>' + title + '</title></head>'
            '<body style="margin:0;padding:0;background:#edf2f7;color:#243247;'
            'font-family:Arial,Helvetica,sans-serif;font-size:14px">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="background:#edf2f7"><tr><td style="padding:24px 12px">'
            '<table role="presentation" align="center" width="100%" cellpadding="0" cellspacing="0" '
            'style="max-width:960px;background:#ffffff;border:1px solid #dce4ee">'
            '<tr><td style="padding:22px 26px;background:#123b65;color:#ffffff">'
            '<div style="font-size:12px;letter-spacing:2px;color:#cbdff2">NETWORK OPERATIONS</div>'
            '<div style="font-size:23px;font-weight:bold;margin-top:8px">' + title + '</div>'
            '<div style="font-size:13px;margin-top:8px;color:#d9e8f5">Báo cáo điều tra &amp; bằng chứng kỹ thuật</div>'
            '</td></tr><tr><td style="padding:8px 26px 26px">'
            + '\n'.join(blocks)
            + '</td></tr><tr><td style="padding:16px 26px;background:#f5f8fc;'
            'border-top:1px solid #dce4ee;color:#607086;font-size:12px;line-height:1.6">'
            'Nội dung báo cáo nằm trực tiếp trong email. Không có file đính kèm.'
            '</td></tr></table></td></tr></table></body></html>')
