"""Read-only export helpers. No scanner, network, model calls, or verdict updates."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import re
from pathlib import Path
from html import escape

VERSION = 'review-report-v1'
VERDICTS = ('LIKELY_TP', 'LIKELY_FP', 'UNKNOWN', 'NOT_RECORDED')
REVIEW_LABELS = {'REVIEWED': 'Đã thẩm định hợp lệ', 'PENDING': 'Chờ thẩm định',
                 'UNAVAILABLE': 'Chưa đủ điều kiện xác nhận thẩm định'}
NOTICE = ('LIKELY_TP và LIKELY_FP là các kết luận có cơ sở, không phải bảo đảm tuyệt đối. '
          'UNKNOWN nghĩa là chưa đủ cơ sở kết luận. Nhãn khớp với thẩm định không tự chứng minh '
          'độ chính xác trên dữ liệu độc lập; không cộng các lượt chạy lại thành mẫu độc lập.')
TIME_NOTE = ('Thời gian toàn lượt tính từ lúc bắt đầu đến kết thúc pipeline, không phải thời gian '
             'riêng của mô hình. Lượt phân tích từ cảnh báo đã lưu không bao gồm lần quét SonarQube trước đó '
             'hoặc thời gian người dùng thẩm định sau khi pipeline kết thúc.')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def evidence_view(ui, folder, entry):
    row, decision = entry['row'], entry['decision']
    artifact = row.get('artifact_dir')
    if not isinstance(artifact, str) or not re.fullmatch(r'issue-\d+', artifact):
        return [], 'Bản ghi không có snapshot mã nguồn.', False
    try:
        raw = ui.run_file(folder, artifact + '/source.java.txt').read_bytes()
        if sha(raw) != row.get('source_sha256'):
            return [], 'Hash mã nguồn không khớp; không xuất đoạn mã làm bằng chứng.', False
        lines = raw.decode('utf-8').splitlines()
    except (OSError, ValueError, UnicodeError) as exc:
        return [], 'Không đọc được snapshot mã nguồn để đối chiếu.', False
    def line_set(value):
        return {n for n in value if type(n) is int and 1 <= n <= len(lines)} if isinstance(value, list) else set()
    ai = line_set(decision.get('ai_evidence_lines'))
    system = line_set(row.get('evidence_lines'))
    issue = row.get('line')
    selected = ai | system | line_set([issue])
    context = {n for center in selected for n in range(max(1, center-2), min(len(lines), center+2)+1)}
    result = []
    last = 0
    for n in sorted(context):
        if last and n != last+1:
            result.append({'n': '…', 'text': '…', 'tags': ''})
        tags = [label for active, label in ((n == issue, 'Sonar'), (n in ai, 'AI'), (n in system, 'Hệ thống')) if active]
        result.append({'n': n, 'text': lines[n-1], 'tags': ', '.join(tags)})
        last = n
    return result, ('Snapshot khớp SHA-256. Trích các dòng được dẫn và tối đa hai dòng xung quanh.'
                    if result else 'Snapshot khớp SHA-256 nhưng chưa có dòng bằng chứng hợp lệ.'), True

def prepare(ui, folder, name, manifest, rows, reviews, hashes):
    entries = ui.build_entries(folder, manifest, rows, reviews)
    warnings = []
    if manifest.get('state') != 'COMPLETED':
        warnings.append('Lượt chưa hoàn tất thành công. Báo cáo chỉ phản ánh dữ liệu hiện có.')
    if manifest.get('result_count') is not None and manifest['result_count'] != len(rows):
        warnings.append('Số bản ghi hiện có khác manifest. Các bảng tính từ dữ liệu hiện có, không dùng tổng cũ.')
    for entry in entries:
        snippet, note, verified = evidence_view(ui, folder, entry)
        entry.update(snippet=snippet, source_note=note, source_verified=verified,
                     review_label=REVIEW_LABELS[entry['review_state']])
        if entry['review_state'] == 'REVIEWED' and not verified:
            entry.update(review_state='UNAVAILABLE', review_label=REVIEW_LABELS['UNAVAILABLE'], review_block=note)
        row = entry['row']
        entry['system_explanation'] = row.get('combined_explanation') or row.get('explanation') or 'Chưa ghi giải thích.'
        entry['is_proposed'] = row.get('processing_status') in ('AI_PROPOSED', 'ANALYZED')
        entry['current_review'] = entry['latest'] if entry['review_state'] == 'REVIEWED' else None
        entry['review_time'] = ui.local_time(entry['latest'].get('saved_at')) if entry['latest'] else ''
        entry['same_explanation'] = entry['system_explanation'] == entry['decision'].get('ai_explanation')
        entry['different'] = entry['is_proposed'] and entry['decision']['ai_verdict'] != entry['label']
        for key, value in [('ai_gaps', entry['decision'].get('ai_missing_context')),
                           ('system_gaps', row.get('missing_context'))]:
            entry[key] = value if isinstance(value, list) else None
    stats = ui.statistics_data(manifest, entries)
    totals = {key: Counter() for key in ('ai', 'system', 'human')}
    for group in stats['groups']:
        for key in totals:
            totals[key].update(group[key])
    metadata = [('Dự án', manifest.get('project') or 'Chưa ghi'), ('Lượt chạy', name),
                ('Trạng thái', manifest.get('state') or 'Chưa ghi'),
                ('SonarQube Analysis ID', manifest.get('analysis_id') or 'Chưa ghi'),
                ('Bắt đầu', ui.local_time(manifest.get('started_at'))),
                ('Kết thúc', ui.local_time(manifest.get('finished_at'))),
                ('Thời gian toàn lượt', stats['duration'] or 'Chưa đủ mốc thời gian hợp lệ')]
    exported_at = ui.local_time(datetime.now(timezone.utc).isoformat())
    return dict(name=name, manifest=manifest, entries=entries, stats=stats, totals=totals,
                metadata=metadata, exported_at=exported_at, warnings=warnings,
                hashes=hashes, version=VERSION, notice=NOTICE, time_note=TIME_NOTE)

def to_pdf(report):
    """Lazily import PDF library; HTML remains available without it."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    fonts = Path(__file__).parent / 'fonts'
    for font_name, filename in [('Review', 'DejaVuSans.ttf'), ('ReviewBold', 'DejaVuSans-Bold.ttf'),
                                ('ReviewMono', 'DejaVuSansMono.ttf')]:
        if font_name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(font_name, str(fonts / filename)))
    pdfmetrics.registerFontFamily('Review', normal='Review', bold='ReviewBold')
    styles = {
        'body': ParagraphStyle('body', fontName='Review', fontSize=9, leading=14, spaceAfter=7, splitLongWords=True),
        'small': ParagraphStyle('small', fontName='Review', fontSize=7.5, leading=11, spaceAfter=5, textColor=colors.HexColor('#536579')),
        'trace': ParagraphStyle('trace', fontName='Review', fontSize=6.5, leading=9, spaceAfter=3, textColor=colors.HexColor('#536579')),
        'title': ParagraphStyle('title', fontName='ReviewBold', fontSize=22, leading=28, spaceAfter=14, textColor=colors.HexColor('#174e60')),
        'heading': ParagraphStyle('heading', fontName='ReviewBold', fontSize=13, leading=18, spaceBefore=12, spaceAfter=7, keepWithNext=True),
        'issue': ParagraphStyle('issue', fontName='ReviewBold', fontSize=18, leading=23, spaceAfter=10, textColor=colors.HexColor('#174e60'),keepWithNext=True),
        'subheading': ParagraphStyle('subheading', fontName='ReviewBold', fontSize=11, leading=15, spaceBefore=8, spaceAfter=5, keepWithNext=True),
        'cell': ParagraphStyle('cell', fontName='Review', fontSize=8, leading=12, alignment=TA_LEFT, splitLongWords=True),
        'code': ParagraphStyle('code', fontName='ReviewMono', fontSize=7.3, leading=10.5, spaceAfter=1, splitLongWords=True),
    }
    def para(value, style='body'):
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value if value is not None else 'Chưa ghi'))
        text = escape(text.expandtabs(4)).replace('\n', '<br/>')
        if style == 'code':
            text = text.replace(' ', '&#160;')
            # DejaVu Sans Mono lacks some Vietnamese glyphs; use the full font for Unicode.
            text = ''.join('<font name="Review">' + char + '</font>' if ord(char) > 127 else char for char in text)
        return Paragraph(text, styles[style])
    def table(data, widths):
        t = Table([[para(c, 'cell') for c in row] for row in data], colWidths=widths, repeatRows=1, hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e9f1f5')),
            ('VALIGN',(0,0),(-1,-1),'TOP'), ('LEFTPADDING',(0,0),(-1,-1),7),
            ('RIGHTPADDING',(0,0),(-1,-1),7), ('TOPPADDING',(0,0),(-1,-1),7),
            ('BOTTOMPADDING',(0,0),(-1,-1),7), ('LINEBELOW',(0,0),(-1,-1),.3,colors.HexColor('#d7e1e9'))]))
        return t
    story = [para('SECURITY REVIEW', 'small'), para('Báo cáo kiểm chứng\ncảnh báo SonarQube', 'title'),
             para('Xuất lúc ' + report['exported_at'] + ' (giờ Việt Nam). Phạm vi: toàn bộ bản ghi của một lượt chạy.', 'small')]
    for warning in report['warnings']:
        story.append(para('Lưu ý: ' + warning))
    for label, value in report['metadata']:
        story.append(para(label + ': ' + str(value), 'small'))
    s = report['stats']
    story += [para('Tổng quan', 'heading'),
        para(f"Bản ghi: {s['total']}   |   Có đề xuất: {s['proposed']}   |   Đã thẩm định: {s['reviews'].get('REVIEWED',0)}   |   Chờ thẩm định: {s['reviews'].get('PENDING',0)}"),
        para('Không đủ điều kiện xác nhận thẩm định: ' + str(s['reviews'].get('UNAVAILABLE',0)), 'small')]
    summary = [['Nguồn kết luận', 'LIKELY_TP', 'LIKELY_FP', 'UNKNOWN', 'Chưa ghi']]
    for key, label in [('ai','AI ban đầu'), ('system','Hệ thống kết hợp'), ('human','Thẩm định hợp lệ')]:
        summary.append([label] + [report['totals'][key].get(v,0) for v in VERDICTS])
    story += [table(summary, [56*mm,30*mm,30*mm,30*mm,24*mm]),
        para('AI và hệ thống chỉ đếm AI_PROPOSED/ANALYZED. Thẩm định chỉ đếm bản mới nhất còn khớp dữ liệu và mã nguồn.', 'small'),
        para('Nguồn quyết định của hệ thống: ' + '; '.join(f'{k}: {v}' for k,v in s['origins'].items()), 'small'),
        para('Trạng thái xử lý: ' + '; '.join(f'{k}: {v}' for k,v in s['statuses'].items()), 'small')]
    groups = [['Nhóm', 'Bản ghi', 'AI ban đầu', 'Hệ thống', 'Thẩm định']]
    for group in s['groups']:
        if group['total']:
            groups.append([group['name'], group['total']] +
                [' / '.join(str(group[key].get(v,0)) for v in VERDICTS) for key in ('ai','system','human')])
    story += [para('Theo nhóm lỗ hổng', 'heading'), table(groups,[43*mm,19*mm,36*mm,36*mm,36*mm]),
              para('Thứ tự nhãn trong mỗi ô: LIKELY_TP / LIKELY_FP / UNKNOWN / chưa ghi.', 'small'),
              para(report['time_note'],'small'), para(report['notice'],'small')]
    if not report['entries']:
        story.append(para('Chưa có bản ghi phân tích. Các số 0 không phải kết luận mã nguồn an toàn.'))
    story += [Spacer(1,3*mm),para('Dữ liệu dùng để xuất · ' + VERSION,'trace')]
    for name, digest in report['hashes'].items():
        story.append(para(name + ': ' + digest,'trace'))
    for e in report['entries']:
        r, d, human = e['row'], e['decision'], e['current_review']
        story += [PageBreak(), para(e['filename'], 'issue'),
            para(str(r.get('component','')) + ' · dòng ' + str(r.get('line','Chưa ghi'))),
            para('Rule: ' + str(r.get('rule','')) + ' | Trạng thái: ' + str(r.get('processing_status','')), 'small'),
            para('AI: ' + str(d['ai_verdict'] or 'Chưa ghi') + ' | Hệ thống: ' + str(e['label'])),
            para('Thẩm định: ' + (str(human.get('reviewed_verdict')) if human else e['review_label'])),
            para('Nguồn kết luận hệ thống: ' + str(d['origin_label']), 'small')]
        if e['different']:
            story.append(para('Nhãn hệ thống khác nhãn AI. Giữ riêng hai kết quả để đối chiếu.'))
        if e['review_block']:
            story.append(para('Điều kiện thẩm định: ' + e['review_block']))
        if r.get('error_kind'):
            story.append(para('Mã lỗi xử lý: ' + str(r['error_kind'])))
        explanations = [('Giải thích đã lưu (AI và hệ thống)' if e['same_explanation'] else 'Giải thích của hệ thống', e['system_explanation'])]
        if not e['same_explanation']:
            explanations.append(('Nhận định AI đã lưu',d.get('ai_explanation') or 'Chưa lưu riêng giải thích AI.'))
        for title, value in explanations:
            story += [para(title,'subheading'),para(value)]
        story.append(para('Thông tin được ghi là còn thiếu','subheading'))
        for title, gaps in [('Thông tin AI ghi còn thiếu',e['ai_gaps']), ('Thông tin hệ thống ghi còn thiếu',e['system_gaps'])]:
            value = '\n'.join(str(v) for v in gaps) if gaps else ('Không có mục thiếu được ghi nhận.' if gaps is not None else 'Chưa lưu riêng.')
            story.append(para(title + ': ' + value,'small'))
        story.append(para('Thẩm định của người dùng','subheading'))
        if human:
            story += [para(f"{human.get('reviewer','')} | {human.get('reviewed_verdict','')} | lần lưu {human.get('revision','')}"),
                      para(str(human.get('notes',''))),para('Thời điểm lưu: ' + e['review_time'] + ' (giờ Việt Nam)','small')]
        else:
            story.append(para(e['review_label']))
            if e['latest']:
                story.append(para('Có bản thẩm định đã lưu trước đây nhưng không tính là hợp lệ trong báo cáo này.','small'))
        story += [para('Mã nguồn và dòng bằng chứng','subheading'),para(e['source_note'],'small')]
        for line in e['snippet']:
            story.append(para(f"{line['n']}: {line['text']}" + (f"   [{line['tags']}]" if line['tags'] else ''), 'code'))
        story += [para('Truy vết','subheading'),para('Issue ID: ' + str(r.get('issue_id','Chưa ghi')),'small'),
                  para('Source SHA-256: ' + str(r.get('source_sha256','Chưa ghi')),'small')]
    output = io.BytesIO()
    doc = SimpleDocTemplate(output,pagesize=A4,leftMargin=20*mm,rightMargin=20*mm,
        topMargin=18*mm,bottomMargin=18*mm,title='Báo cáo kiểm chứng cảnh báo SonarQube',author='Security Review')
    def footer(canvas, doc):
        canvas.saveState();canvas.setFont('Review',7);canvas.setFillColor(colors.HexColor('#536579'))
        canvas.drawString(20*mm,10*mm,'Security Review · ' + VERSION)
        canvas.drawRightString(190*mm,10*mm,'Trang ' + str(doc.page));canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return output.getvalue()
